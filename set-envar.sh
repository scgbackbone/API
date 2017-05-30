#!/bin/bash

# In case you have LinuX, I found this way to be very efficient.
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

echo "Success..."
