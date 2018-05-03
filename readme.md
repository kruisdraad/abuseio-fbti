
# Install requirements
- MongoDB 3.6 : https://docs.mongodb.com/manual/tutorial/install-mongodb-on-ubuntu/
- MongoDB PHP driver: 
  pecl install mongodb
  echo "extension=mongodb.so" >> `php --ini | grep "Scan for additional .ini" | sed -e "s|.*:\s*||"`/30-mongodb.ini

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
