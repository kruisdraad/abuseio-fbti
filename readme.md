# This does NOT work
this code is alpha at best, it does not work, gives loads of PHP errors. Just wait until
it is finished, ok?

# Install requirements
- Install Ubuntu 16.04 DB with Elasticsearch and Kibana
- Install Ubuntu 16.04 WEB with following packages:
  ````  
  apt-get install php7.0-dev php7.0-cli php7.0-zip php7.0-json php-pear php7.0-mysql 
  apt-get install composer libapache2-mod-php7.0 php7.0-mcrypt php7.0-mbstring whois
  apt-get install apache2 pwgen mysql-server git php7.0-curl
  ````
- Enable Apache modules
  ````
   a2enmod headers
   a2enmod rewrite
   a2enmod ssl
   a2enmod proxy
   a2enmod proxy-http
   a2enmod remoteip
  ````
- YOU MUST Set a 32byte APP_KEY 
- You MUST enable SSL on your endpoint (at apache here, or at haproxy)
- You SHOULD use haproxy with 3 backend WEB nodes
- You SHOULD use ES with 2 copies (its prolly hardcoded at this moment :>)
- You SHOULD tune apache to allow MASSSIVE updating from remote endpoints (!)
- You SHOULD tune sysctl while your at it
- Restart Apache2 after enabling modules and/or changing PHP settings!

# Get Facebook access
- sign up with facebook with a PERSONAL ACCOUNT (!)
- visit https://developers.facebook.com
- create application
- collect the application ID from the newly generated app (put into ENV)
- open the app dashboard by clicking the the app name
= In the left menu, open settings->basic. Add a privacy policy (required!)
- In the upper richt click the status towards LIVE
- In the left menu click op the + after PRODUCTS and select webhook, and add it
- The reporting URL will be vhost/get_report
- The token will be the code you have in ENV file.
- Collect the application 'App Token' from: https://developers.facebook.com/tools/accesstoken (put into ENV)
- Visit https://graph.facebook.com/threat_exchange_members?access_token=APP_TOKEN_HERE and check for errors
- run: php artisan threatex:subscribe
- run: php artisan threatex:subscriptions
- The last command should list a few feeds that are enabled. If not then your screwed (todo docs)

# Todo
- move handler into a queue for asym with error handling
- add more logging
- collect alerts from facebook app
- make CLI commands/autodetect to manage subscriptions
