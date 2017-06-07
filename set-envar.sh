#!/bin/bash

# In case you have LinuX or Mac OSX using bash, I found this way to be very efficient.
# Run the script to export environment variables for a current shell session
# and all child processes. However, you cannot run it the usual way`
# ./scriptname.sh
# you want the script to be executed in current shell, above would execute
# it in subshell
# correct way:
# . ./scriptname.sh
# or 
# source ./scriptname.sh

export SECRET_KEY='super_secret_key'
export MAIL_USERNAME='somehuman@mail.com'
export MAIL_PASSWORD='strong_password'
export DEV_DATABASE_URI='development_database_uri'
export TEST_DATABASE_URI='testing_database_uri'
export DATABASE_URI='production_database_uri'
# here are 4 options: development(default), production, testing, default
export FLASK_CONFIG='default'

echo "Success..."

# for windows users
# command: 

#set SECRET_KEY='super_secret_key'
#set MAIL_USERNAME='somehuman@mail.com'
#set MAIL_PASSWORD='strong_password'
# etc...
