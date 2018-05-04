
# Install requirements
- Install Ubuntu 16.04 with following packages:
  ````  
  apt-get install php7.0-dev php7.0-cli php7.0-zip php7.0-json php-pear php7.0-mysql 
  apt-get install composer libapache2-mod-php7.0 php7.0-mcrypt php7.0-mbstring whois
  apt-get install apache2 pwgen mysql-server git php7.0-curl
  ````
- MongoDB 3.6 : https://docs.mongodb.com/manual/tutorial/install-mongodb-on-ubuntu/
- MongoDB PHP driver: 
  ````
  pecl install mongodb
  echo "extension=mongodb.so" >> /etc/php/7.0/cli/conf.d/30-mongodb.ini
  echo "extension=mongodb.so" >> /etc/php/7.0/apache2/conf.d/30-mongodb.ini
  ````
- Change PHP settings:
  ````
  max_execution_time = 300
  max_input_time = 300
  memory_limit = 512M
  post_max_size = 100M
  upload_max_filesize = 100M
  max_file_uploads = 200
  ````
- Restart Apache2 after enabling MongoDB and changing php settings!

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
- The token will be the code you have in ENV file
- Collect the application 'App Token' from: https://developers.facebook.com/tools/accesstoken (put into ENV)
- Visit https://graph.facebook.com/threat_exchange_members?access_token=APP_TOKEN_HERE and check for errors
- Add the feeds (todo, describe this)

# Todo
- move handler into a queue for asym with error handling
- add more logging
- collect alerts from facebook app
- make CLI commands/autodetect to manage subscriptions