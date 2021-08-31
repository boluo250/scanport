import nmap
import datetime
import os
import json
import multiprocessing 


g_tmp_json_file = "open_port.json"
g_masscan_args="10.18.10.0/24 -p 1-10000 --rate 20000 -oJ %s" % g_tmp_json_file
g_nmap_args = "-v -O"

tored = lambda s: "\033[1;31m%s\033[0m" % s
togreen = lambda s: "\033[1;32m%s\033[0m" % s

def scanPort():


	print("start scan port......")
	cmd = "/root/masscan/bin/masscan %s" % (g_masscan_args)
	print(togreen(cmd))

	begin_time = datetime.datetime.now()
	os.system(cmd)
	end_time = datetime.datetime.now()

	run_time = "masscan scan time: %ss" % (end_time-begin_time).seconds
	print(togreen(run_time))

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
	
def parsePort(ip, port_info_list, share_write_json_dict, share_lock):

	print("start parse port......")
	
	
	port_list = []
	for d in port_info_list:
		port_list.append(str(d["port"]))

	port_str = ",".join(port_list)

	nm = nmap.PortScanner()
	
	begin_time = datetime.datetime.now()

	ret = nm.scan(hosts=ip,ports="%s" % port_str,arguments="%s" % g_nmap_args) #only -v run very fast

	end_time = datetime.datetime.now()
	print("nnmap scan time: ", (end_time-begin_time).seconds,"s")

	for host in nm.all_hosts():
		print(host,nm[host].hostname(),nm[host].state())
		print(nm[host])
		if nm[host].state() == "up":
			
			
			if host in share_write_json_dict:
				pass
			else:
				share_write_json_dict[host] = ""
			"""
			print(nm[host].tcp(6000))
			print(nm[host].tcp(135))
			print(nm[host].tcp(123))
			print(nm[host]["addresses"]["mac"])
			print(nm[host].tcp(6000)["name"])
			print(nm[host].tcp(6000)["version"])

			"""

def mutilProcessRun(ip_info_dict):

	share_write_json_dict = multiprocessing.Manager().dict()
	share_lock = multiprocessing.Manager().Lock()

	print("cpu num: %d" % multiprocessing.cpu_count())
	pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())
	for ip, port_info_list in ip_info_dict.items():
		pool.apply_async(parsePort, (ip, port_info_list,share_write_json_dict, share_lock, ))

	pool.close()
	pool.join()

	print(share_write_json_dict)

	return share_write_json_dict

def main():

	begin_time = datetime.datetime.now()

	#scanPort()
	ip_info_dict = loadTmpJson()
	share_write_json_dict = mutilProcessRun(ip_info_dict)

	end_time = datetime.datetime.now()

	run_time = "\nrun time: %ss" % (end_time-begin_time).seconds
	print(togreen(run_time))

if __name__ == '__main__':
	main()