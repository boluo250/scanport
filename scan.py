import nmap
import datetime
import os
import json
import multiprocessing 


g_tmp_json_file = "open_port.json"
g_masscan_cmd="/root/masscan/bin/masscan 10.18.10.0/24 -p 1-10000 --rate 20000 -oJ %s" % g_tmp_json_file
g_nmap_args = "-v -O"

tored = lambda s: "\033[1;31m%s\033[0m" % s
togreen = lambda s: "\033[1;32m%s\033[0m" % s


def timer(function):

	def wrapper(*args, **kwargs):
		p = "[%s] start" % function.__name__
		print(togreen(p))
		begin_time = datetime.datetime.now()
		res = function(*args, **kwargs)
		end_time = datetime.datetime.now()
		run_time = "[%s] run time: [%s]s" % (function.__name__,(end_time-begin_time).seconds)
		print(togreen(run_time))
		return res

	return wrapper

@timer
def scanPort():

	os.system(g_masscan_cmd)
	
@timer
def loadTmpJson():

	ip_info_dict = {}
	if os.path.exists(g_tmp_json_file):
		with open(g_tmp_json_file, "r") as f:
			for line in f:
				if line.startswith("{"):
					tmp_dict = {}
					
					tmp_info_dict = json.loads(line)

					ip = tmp_info_dict["ip"]
					ports_info_dict = tmp_info_dict["ports"][0]
					tmp_dict["timestamp"] = tmp_info_dict["timestamp"]
					tmp_dict["port"] = ports_info_dict["port"]
					tmp_dict["proto"] = ports_info_dict["proto"]
					if ip not in ip_info_dict:
						ip_info_dict[ip] = []
				
					ip_info_dict[ip].append(tmp_dict)
	else:
		print(tored("masscan scan not find open port!"))

	print(ip_info_dict)

	return ip_info_dict


def parsePort(ip, port_info_list, share_write_json_list, share_lock):

	
	port_list = []
	for d in port_info_list:
		port_list.append(str(d["port"]))

	port_str = ",".join(port_list)

	nm = nmap.PortScanner()
	
	ret = nm.scan(hosts=ip,ports="%s" % port_str,arguments="%s" % g_nmap_args) #only -v run very fast

	#for host in nm.all_hosts():
	nmap_ip_info = nm[ip]
	print(ip,nmap_ip_info.hostname(),nmap_ip_info.state())
	print(nmap_ip_info)
	#print(nm.csv())

	if nmap_ip_info.state() == "up":

		my_port_list = []

		for proto in nmap_ip_info.all_protocols():
			for port in nmap_ip_info[proto].keys():
				if nmap_ip_info[proto][port]["state"] == "open":
					my_port_dict = {}
					my_port_dict["port"] = port
					my_port_dict["server"] = nmap_ip_info[proto][port]["name"]
					my_port_dict["version"] = nmap_ip_info[proto][port]["version"]
					my_port_dict["protocol"] = proto
					my_port_list.append(my_port_dict)

		if my_port_list:
			my_ip_dict = {}
			my_ip_dict["ip"] = ip
			my_ip_dict["mac"] = nmap_ip_info["addresses"]["mac"]
			my_ip_dict["discoveryTime"] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			my_ip_dict["os"] = nmap_ip_info["osmatch"][0]["name"]
			my_ip_dict["osVersion"] = ""
			my_ip_dict["taskId"] = ""
			my_ip_dict["ports"] = my_port_list

			share_lock.acquire()
			share_write_json_list.append(my_ip_dict)
			share_lock.release()



@timer
def mutilProcessRun(ip_info_dict):

	share_write_json_list = multiprocessing.Manager().list()
	share_lock = multiprocessing.Manager().Lock()

	print("cpu num: %d" % multiprocessing.cpu_count())
	pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())
	for ip, port_info_list in ip_info_dict.items():

		pool.apply_async(parsePort, (ip, port_info_list,share_write_json_list, share_lock, ))

	pool.close()
	pool.join()

	print(share_write_json_list)

	return share_write_json_list

@timer
def writeJsonFile(share_write_json_list):

	now_time = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
	json_file = "%s.json" % now_time
	with open(json_file, "w") as f:
		json.dump(list(share_write_json_list), f)

@timer
def main():

	#scanPort()
	ip_info_dict = loadTmpJson()
	share_write_json_list = mutilProcessRun(ip_info_dict)
	writeJsonFile(share_write_json_list)

if __name__ == '__main__':
	main()