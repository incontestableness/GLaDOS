#!/usr/bin/env bash

echo "The configurations in ./WSGI/ and ./logrotate.d/ assume the domain name milenko.ml, runtime username nyrx, and ServerAdmin email whyistherumg0ne@protonmail.com."
read -p "Press enter to continue..."; echo

sudo apt install python3-pip apache2 libapache2-mod-wsgi-py3 -y
pip3 install -r requirements.txt
echo -e "\nInsert the \"ServerName yourdomainhere\" directive into /etc/apache2/apache2.conf before proceeding."
echo "Consider also setting the ServerAdmin contact in /etc/apache2/sites-available/000-default.conf"
read -p "Press enter when done..."; echo

echo "Setting up static content..."
sudo rmdir /var/www/html && sudo git clone https://github.com/incontestableness/milenko.ml /var/www/ && sudo chown -vR $USER /var/www/.git /var/www/html

echo -e "\nConfiguring apache2 logrotate to softly restart GLaDOS..."
sudo cp -v logrotate.d/apache2 /etc/logrotate.d/apache2

echo -e "\nSetting up WSGI..."
sudo cp -vr WSGI/* /etc/apache2/
sudo a2enmod headers
sudo a2ensite GLaDOS.conf
sudo systemctl reload apache2

echo -e "\nAll done."
