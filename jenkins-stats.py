import getopt, sys
import os,time
import logging
import glob
import codecs
import getpass
#import vcr
try:
	import requests
except ImportError:
    sys.stderr.write("\nError: please install python requests module first: http://www.python-requests.org/\n")

from requests.auth import HTTPBasicAuth
from string import Template
import getpass
import json

currenttime = time.asctime(time.localtime())

LARRY_TOKEN   = "a2310b1f6b7d584495ebbf9b347244e9fee"
TEMPLATE_FILE = "plugin_usage_template.html"
DETAIL_TEMPLATE_FILE = "detail_plugin_jobs_template.html"
INDEX_HTML    = "index.html"
DETAIL_DIR    = "detail"
SHALL_DETAIL  = True
LIMIT_JOBS    = 20
SYSTEM_VIEW_CFG = "views.config_xml"
prop = {
	"user" : "larry", # will set to current user as default
	"token" : LARRY_TOKEN,
	"dir" : "jenkinsBackup",
	"config" : "jenkins.cfg",
	"passwd" : False,
	"url" : "https://jenkins-server/",
}


def get_job_config(url,name):
	config_url = "%s/job/%s/config.xml" % (url,name)

	#with vcr.use_cassette('fixtures/debug3.yaml'):
	# 	j = jenkins.Jenkins(url, 'rdccaiy', 'a231094d044ca829d367f35829085036')
	r = requests.get(config_url,verify=False,auth=HTTPBasicAuth(prop["user"], prop["token"]))
	if r.ok:
		return r.text
	else:
		raise Exception("can't fetch data from %s using user: %s, token: %s" % (config_url,prop["user"], prop["token"]))

def get_jobs_from_view(url,view):

	jobs_url = "%s/view/%s/api/json" % (url, view)
	r = requests.get(jobs_url, verify=False,auth=HTTPBasicAuth(prop["user"], prop["token"]))
	if r.ok:
		return r.json()
	else:
		raise Exception("can't fetch data from %s using user: %s, token: %s" % (jobs_url,prop["user"], prop["token"]))

def get_views_config(url):
	config_url = "%s/config.xml" % (url)

	#with vcr.use_cassette('fixtures/debug3.yaml'):
	# 	j = jenkins.Jenkins(url, 'rdccaiy', 'a231094d044ca829d367f35829085036')
	r = requests.get(config_url,verify=False,auth=HTTPBasicAuth(prop["user"], prop["token"]))
	if r.ok:
		return r.text
	else:
		raise Exception("can't fetch data from %s using user: %s, token: %s" % (config_url,prop["user"], prop["token"]))

def get_plugins(url):
	plugin_url = "%s/pluginManager/api/json?depth=1" % url
	#with vcr.use_cassette('fixtures/debug_jobs.yaml'):
	r = requests.get(plugin_url, verify=False, auth=HTTPBasicAuth(prop["user"], prop["token"]))
	if r.ok:
		return r.json()["plugins"]
	else:
		raise Exception("can't fetch data from %s using user: %s, token: %s" % (plugin_url,prop["user"], prop["token"]))

def get_jobs(url):
	jobs_url = "%s/api/json" % url
	r = requests.get(jobs_url, verify=False,auth=HTTPBasicAuth(prop["user"], prop["token"]))
	if r.ok:
		return r.json()["jobs"]
	else:
		raise Exception("can't fetch data from %s using user: %s, token: %s" % (jobs_url,prop["user"], prop["token"]))

def list_plugins(url):
	print ("start to list installed plugins in url:", url)
	plugin_list = get_plugins(url)
	for plugin in plugin_list:
		#print ("%s (%s): version : %s") % (plugin["longName"],plugin["shortName"], plugin["version"])
		 print ("{0} ({1}): version : {2}".format(plugin["longName"],plugin["shortName"], plugin["version"]))
		# if plugin["shortName"] == "git":
		# 	print plugin
	#print ("total %d plugins") % len(plugin_list)
	print ("total %{0}  plugins".format(len(plugin_list)))

def list_jobs(url):
	print ("start to list all jobs in url:", url)
	job_list = get_jobs(url)
	for job in job_list:
		print (job["name"],job["color"]) #,job

	print ("\nTotal {0} jobs".format(len(job_list)))
	return job

def load_plugin_keywords():
	config = json.load(open(prop["config"]))
	plugins_config = {}
	for plugin in config["jobs"]["simple"]:
		plugins_config[plugin] = ["jobs",""]

	for plugin in config["views"]["simple"]:
		plugins_config[plugin] = ["views",""]

	for plugin in config["system"]:
		plugins_config[plugin] = ["system",""]
	#print plugins_config
	return plugins_config

def check_jobs(url,name,key,config_files,plugin):
	count = 0
	detail_html=""
	detail_table_data = ""

	for fl in config_files:
		#print fl
		# http://docs.python.org/2/howto/unicode.html
		if key in codecs.open(fl,encoding="utf-8",errors="ignore").read():
			jobname = os.path.splitext(os.path.basename(fl))[0]

			count = count +1
			if count < LIMIT_JOBS:
				job_url = "<a href='%s/job/%s/' target='_blank'>%s</a>, " % (url, jobname,jobname)
				detail_html += job_url
			elif count == LIMIT_JOBS:
				detail_html += "..."
			else:
				pass # don't append more
			if SHALL_DETAIL:
				detail_table_data += ' \
				<tr class="gradeA"> \n \
					<td><a href="%s">%s</a></td>\n \
					<td class="center"><a href="%s/job/%s" target="_blank">%s</a></td>\n \
				</tr>\n' % (plugin["url"],plugin["longName"],url,jobname,jobname)

	if count and SHALL_DETAIL:
		DETAIL_INDEX_HTML = "%s/%s.html" % (DETAIL_DIR,name)
		detailTemplateFilename = DETAIL_TEMPLATE_FILE
		detailTemplate = open(detailTemplateFilename).read()
		detail_html_contents = Template(detailTemplate).safe_substitute(detail_table_data=detail_table_data,currenttime=currenttime)

		with open(DETAIL_INDEX_HTML,"w") as fp:
			fp.writelines(detail_html_contents);
	detail_url = "0"
	if count:
		detail_url = '<a href="%s/%s.html" target="_blank">%d</a>' % (DETAIL_DIR,name,count)
	cell_data = '<td class="center hide" details="%s">%s</td>' % (detail_html,detail_url)

	jobs_url = "%s/api/json?pretty=true" % url

	type_data = '<td class="center"><a href="%s" title="list all jobs" target="_blank">jobs</a></td>' % jobs_url

	return count, cell_data, type_data

def check_views(url,key):
	count = 0
	config_dir = prop["dir"]
	config_url = "%s/config.xml" % url
	detail_url = "0"

	config_file = os.path.join(config_dir + "/" + SYSTEM_VIEW_CFG)
	if key in codecs.open(config_file,encoding="utf-8",errors="ignore").read():
		count = 1
		detail_url = '<a href="%s" target="_blank">%d</a>' % (config_url,count)

	cell_data = '<td class="center hide" details="">%s</td>' % (detail_url)
	type_data = '<td class="center"><a href="%s" title="list all views" target="_blank">views</a></td>' % config_url
	return count, cell_data, type_data

def check_systems():
	count = 1
	cell_data = '<td class="center">1</td>'
	type_data = '<td class="center">system</td>'
	return count, cell_data, type_data

def scan_plugins(url):
	config_dir = prop["dir"]
	config_files = glob.glob(config_dir + "/*.xml")

	print ("start to scan the config files for installed plugins")
	print ("1. start to check the plugins in url:", url)
	print ("2. scan {0} the config files under {1}".format(len(config_files),config_dir))

	if len(config_files) == 0:
		print ("no config.xml are found, please dump first")
		return

	global_plugins = load_plugin_keywords()

	if SHALL_DETAIL:
		if not os.path.exists(DETAIL_DIR):
			print ("create dir: ", DETAIL_DIR)
			os.makedirs(DETAIL_DIR)

	plugin_list = get_plugins(url)
	total = len(plugin_list)

	table_data = ""
	for idx, plugin in enumerate(plugin_list):
		name = plugin["shortName"]
		#print ("plugin %3d/%d: %s (%s)") % (idx+1, total, plugin["longName"], name) ,
		print ("plugin {0:3d}/{1}: {2} ({3})".format(idx+1, total, plugin["longName"], name))

		# <org.jenkins.ci.plugins.html5__notifier.JobPropertyImpl plugin="html5-notifier-plugin@1.2">
		plugin_cfg = ["",""]
		status = "?"
		if name in global_plugins:
			plugin_cfg = global_plugins[name]
			status = "="

		plugin_type, key = plugin_cfg
		if plugin_type == "":
			plugin_type = "jobs"
		if key == "":
			key = 'plugin="' + name #
		else:
			status = "*"

		count = 0
		cell_data = '<td class="center">0</td>'
		type_cell_data = '<td class="center">jobs</td>'
		if plugin_type == "system":
			count,number_cell_data,type_cell_data = check_systems()
		elif plugin_type == "views":
			count,number_cell_data,type_cell_data = check_views(url,key)
		elif plugin_type == "jobs":
			count,number_cell_data,type_cell_data = check_jobs(url,name,key,config_files,plugin)

		if count and status == "?":
			status = "="

		if status == "?":
			type_cell_data = '<td title="need to add information in jenkins.cfg" class="center">unknown</td>'

		table_data += ' \
		<tr class="gradeA"> \n \
			<td><a href="%s">%s</a></td>\n \
			<td class="shortname">%s</td>\n \
			%s \n \
			<td class="center">%s</td>\n \
			%s \n \
		</tr>\n' % (plugin["url"],plugin["longName"], name, number_cell_data, plugin["version"],type_cell_data)
		print ("found {0} jobs".format(count))

	templateFilename = TEMPLATE_FILE
	template = open(templateFilename).read()
	html_contents = Template(template).safe_substitute(table_data=table_data,currenttime=currenttime)

	with open(INDEX_HTML,"w") as fp:
		fp.writelines(html_contents);

	print ("\nThe result is output to {0}, enjoy".format(INDEX_HTML))

	if SHALL_DETAIL:
		print ("\nThe detail result is output to {0}, enjoy".format("detail"))

def dump_config(url):
	dest_dir = prop["dir"]
	print ("start to dump all jobs' config.xml to {0} in url: {1}".format(dest_dir, url))
	job_list = []
	if "view" in prop:
		job_list = view_jobs_list(url)
	else:
		job_list = get_jobs(url)
	if not os.path.exists(dest_dir):
		print ("create dir: ", dest_dir)
		os.makedirs(dest_dir)
	total = len(job_list)
	print ("total {0} jobs' config will be dumpped".format(total))

	for idx, job in enumerate(job_list):
		name = job["name"]
		config = get_job_config(url, name).encode('utf-8', 'ignore')
		output_file = os.path.normpath(os.path.join(dest_dir, name + ".xml"))

		#print (" %4d/%d dump output file %s") % (idx+1, total, output_file)
		print ("{0:4d}/{1} dump output file {2}".format(idx+1, total, output_file))
		# loop for all variables to print out
		with open(output_file,"w") as fp:
			fp.write(str(config))

	print ("total {0} jobs' config are dumpped".format(len(job_list)))

	config = get_views_config(url).encode('utf-8', 'ignore')
	output_file = os.path.normpath(os.path.join(dest_dir, SYSTEM_VIEW_CFG))

	print ("views config.xml file is save to file {0}".format(output_file))
	# loop for all variables to print out
	with open(output_file,"w") as fp:
		fp.write(str(config))

def get_jobs_list_from_view(url,view):
	print ("==> check view:", view)
	cfg = get_jobs_from_view(url,view)
	jobs = cfg["jobs"]
	if "views" in cfg:
		views = cfg["views"]
		print (view, ":", views)
		for vw in views:
			print (vw,vw["name"])
			jobs.extend(get_jobs_list_from_view(url, view + "/view/" + vw["name"]))
		print (jobs)
		return jobs
	else:
		print ("======> got jobs list:", jobs)
		return jobs

def view_jobs_list(url):
	view = prop["view"]
	job_list = get_jobs_list_from_view(url,view)
	print (job_list)
	#for job in job_list:
	#	print job["name"],job["color"] #,job
	print ("\nTotal {0} jobs".format(len(job_list)))

	#http://stackoverflow.com/questions/11092511/python-list-of-unique-dictionaries
	unique_job_list = { v['name']:v for v in job_list }.values()
	print ("\nTotal {0} jobs".format(len(unique_job_list)))
	return unique_job_list
	#return job

def jenkins_stat(task):
	url = prop["url"]

	#print ("[task]: %s %s (user=%s)") % (task,url,prop["user"])
	print ("[task]: {0} {1} (user={2})".format(task,url,prop["user"]))

	if task == "plugins":
		list_plugins(url)
	elif task == "dump":
		dump_config(url)
		#config = get_job_config(url, "ADM_LABEL_SBA").encode('utf-8', 'ignore')
		#print config
	elif task == "jobs":
		list_jobs(url)
	elif task == "scan":
		scan_plugins(url)
	elif task == "debug": # this is internal for debug of hidden features
		view_jobs_list(url)
	else:
		print ("task", task, "is not supported")

def main():
	#logging.basicConfig(level=logging.DEBUG)
	global prop
	task = "plugins"
	prop["user"] = getpass.getuser().lower()

	try:
	    cmdlineOptions, args= getopt.getopt(sys.argv[1:],'hu:a:t:o:c:d:l:pv:',
	        ["help","token=","task=","user=","output=","dir=","url=","config=","passwd","view="])
	except getopt.GetoptError as e:
	    print ("Error in a command-line option:\n\t" ,e)
	    sys.exit(1)

	for (optName,optValue) in cmdlineOptions:
	    if  optName in ("-h","--help"):
	        print (__doc__)
	        sys.exit(1)
	    elif optName in ("-d","--dir"):
	        prop["dir"] = optValue
	    elif optName in ("-c","--config"):
	        prop["config"] = optValue
	    elif optName in ("-t","--task"):
	        task = optValue
	    elif optName in ("-p","--passwd"):
	        prop["passwd"] = True
	    elif optName in ("-u","--user"):
	        prop["user"] = optValue
	    elif optName in ("-l","--url"):
	        prop["url"] = optValue
	    elif optName in ("-o","--token"):
	        prop["token"] = optValue
	    elif optName in ("-v","--view"):
	        prop["view"] = optValue
	    else:
	        print ('Option %s not recognized' % optName)

	if prop["passwd"]:
		prop["token"] = getpass.getpass("Enter your ({0}) windows password: ".format(prop["user"]))
	elif prop["token"] == LARRY_TOKEN:
		print ("\n\t!!! Please use your own token to access jenkins server or use -p to enter your passwd !!! \n")

	jenkins_stat(task)

if __name__ == "__main__":
	main()