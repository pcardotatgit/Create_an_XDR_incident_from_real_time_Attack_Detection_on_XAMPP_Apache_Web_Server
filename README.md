# Create an XDR incident from real time Attack Detection on XAMPP Apache Web Server

This script is a proof of concept of creation of an XDR Incident from a security log file analysis.

In this proof of concept is an improvement of the  [XDR_demo_-_create_incident_from_apache_log_threat_analysis  ](https://github.com/pcardotatgit/XDR_demo_-_create_incident_from_apache_log_threat_analysis) project.

In this project above the script reads the Web Server's log file an detect into it every Web Attacks it contains ( and then create XDR Incident ). Threat Detection is not real time, but done only when the script is runt.

In this current project the script reads the Web Server's log file in real time in the background. This script actually run only under windows machines. it uses win32 system APIs and actually it leverage the capability to monitor files in order to detect any changes on it.

We designate the Web Server log file as the file to monitor. This log file is constantly updated by the Web server when users connect to it.  The script listens in the background to every changes. And copy every new lines that are added into the log file. Then we apply in real time, to the new copied line, an IDS check in order to detect any Web Attack into the targeted URL. And if an attack is found then the script create in real time an Incident into XDR.  

A perfect use case for this script is to be installed in addition a XAMPP web server for windows. 

No need to do any configuration on the web server.

We just have to configure the name and the full path of the apache web server into the script configuration and then run the script.

A great thing is that this script is not dedicated to apache log files. It can be used to monitor the same way any text file within the windows machines ! 

The file to monitor must be a text file, and the signatures must be customized depending on the purpose of the script. 

Generating alerts from any log file is a perfect use case for this script.

This use case is a good example of something to deploy in production on an honeypot for example. It is very easy to deploy.

You just have to setup an Honeypot Apache Web Server ( XAMPP )on a windows machine. With the phpmyadmin application installed but without a MySQL database. We don't really need a real MySQL database except if you plan to study MySQL database infection. 

And then expose your web server on the INTERNET.

Within a few hours your web server will be discovered by INTERNET Bad guys ( mostly bots ) and you will see Web attacks coming. 

These attacks will be visible into the apache access.log file. 

And the principle of this monitoring system is very simple. As this Web Server is not a production server ( this is an honeypot ) any one who discorver the phpmyadmin application and then tries to log into it, is a confirmed bad guy. So we can add his IP address into our blocking list.

The script captures in real time apache new lines into  the log file and fire up instantly an XDR Incident if an attempt acces to phpmyadmin is seen.

Here is an example of web get call which is detected :

    GET /phpmyadmin/index.php?pma_username=root&pma_password=anything
    http://web_server_address/phpmyadmin/index.php?pma_username=root&pma_password=anything
    

## More details about the application

Every threat detected is logged into a resulting report file in the **./logs** subfolfer into the **./logs/out.txt**.

This **./out** file  will contain absolutely every threats detected.

But only one of this threats will create an **XDR Incident**. This is the **Admin Access Attempt to phpmyadmin threat** which is easily visible into the apache log file. 

This is an arbitrary rule we decide, because that one seems to be good to filter IP source addresses which show real malicious intentions. These malicious IP addresses are 100 % confirmed malicious as the server is an honeypot. 

The core of the application is the **1-real_time_web_attack_detection_and_alert.py** script. This is the script to run.

The XDR Incident Creation is managed by the **create_XDR_incident.py** script. You will probably recognize it if you went thru the [XDR_create_incident_with_python ](https://github.com/pcardotatgit/XDR_create_incident_with_python) article.

In this repo, this is exactly the same script, just a little bit modified to make it fit to this use case. It is uses as a ressource by the **1-real_time_web_attack_detection_and_alert.py** script.

The **1-real_time_web_attack_detection_and_alert.py** script must be runt in the background permanently. It consomue a very few CPU resources and then it is perfect for a production Honeypot. 

It contains the Threat Detection engine. This is a partern matching engine which search for signatures into every captured log lines. 

The signatures are statically defined into the python script into the **check_ids_signature(line)** function and basically these signatures search of one or two strings into the log line, and time to time count for occurences of these strings. As the Web Server is not a production server but a honeypot, everyone who connect to it, is by definition suspicious then we just confirm this by very basic search on partern that confirm us that. This is a technical choice. Very easy, extrimely fast, very efficient.

The first intention of this script was XDR demos. So in this context no need to do complex things.

But this script is a very interesting candidate for heavy used production web server. Then in tis other context the check_signature function disearves to be improved with more signatures and advanced correlation. This is not the purpose of this project but we have a nnext step for this project.  

Don't hesitate to have a look to the signatures add your own.

Incident promotion to XDR is done in real time.

Malicious observables are added into an XDR Incident everytime we detect an attack done by it. This observable is the IP source address of the attacker. We don't do any deduplication. An Incident is created for every attack detected. Here is another improvement area for this script.

Regarding the target JSON payload, as we only have one target ( the honeypot web server ) and we already know it I decided to declare it into static variable into the **def get_targets()** function.

If you want to customize this script for another use case, then you have to modify the **def get_targets()** and **keep_this_ip_in_observables()** functions and make them parse the source and create the observable, target list and observable relationships.

## Installation

Copy the application directory structure into a working directory of the windowsweb server.  Open a CMD console into this directory. It is a good practice to create an python virual environement.

You need to install the following python modules

    pip install crayons
    python -m pip install pywin32

## Run the application

First edit the **1-real_time_web_attack_detection_and_alert.py** script and indicate to the script where is the text file to monitor.

Set the correct values  for the variables :

- path_to_watch = "C:\\dir-1\\subdir-1\\subdir-2\\log_file_subdir_location"
- file_to_watch = "access_log" # look for changes to a file called access_log*

Second edit the **config.txt** file and assign the correct values to the application variables. They are the XDR API credential needed for creating Incidents

Second run the application 

    python 1-real_time_web_attack_detection_and_aler.py
   
Then the python script is supposed to run permanently.

In order to test the application open your browser to the web server. 

You will see an log file update message for every connexion you will do into the web server. This confirm you that the application is actively monitoring the web server log file.

Then test the XDR Incident creation by sending to the server a web call that tries to log into phpmyadmin

    http://web_server_address/phpmyadmin/index.php?pma_username=root&pma_password=anything
    
In the application console you will see the log line and at the same time you will see the XDR Incident creation.

The incident will appear into XDR Incident Manager just after that.

## Stop the script

This script uses an infinite loop and it doesn't stop when we uuse CTRL-C.

Actually if we do a CTRL-C we have to wait for a new web connexion to the web server before seeing the script stop.

For this reason there is a specific statement whch stop the script when we send to the Web server the following path into the URL :

    /stopwatching
    http://web_server_address/stopwatching

The script will stop if you send this to the web server from you browser.
    
## Clean Up demo data

Run the **2-delete_XDR_demo_data.py** script in order to completely clean up Data created into XDR.



