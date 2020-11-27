import smtplib
import datetime, boto3, os, json
import re 
from datetime import date, timedelta
from botocore.exceptions import ClientError
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Set the global variables
keyAge = int(os.getenv('key_age',90))
keysDateDifference = int(os.getenv('disable_keys_date_difference',7))
deleteKeysDateDifference = int(os.getenv('delete_keys_date_difference',30))

fromEmail= str(os.getenv('from_email','administrator@xyz.org'))
fromName = str(os.getenv('from_name','Administrator'))
ccEmail = str(os.getenv('cc_email','abc@xyz.org))

smtpHost = str(os.getenv('smtp_host','10.10.10.127'))
smtpPort = str(os.getenv('smtp_port','25'))

# Make a regular expression 
# for validating an Email 
regex = '^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'

iamUsersToCheck = ['user@pqr.com']
xyzOrgEmail = ['user@xyz.com']
pqrSolutionsEmail = ['user@pqr.com']

xyzOrgDomainName = "xyz.org"
pqrSolutionsDomainName = "pqr.com"

def get_usr_old_keys():
    emailSent = 'false' 
    client = boto3.client('iam')    

    emailMessage = ""
   
    paginator = client.get_paginator('list_users')
    for page in paginator.paginate():
        for user in page['Users']:
            userName = user['UserName']
            accessKeys=client.list_access_keys(UserName=userName)
            lengthAccessKeyMetadata = len(accessKeys['AccessKeyMetadata'])
        
            if userName in iamUsersToCheck:
                usrsWithOldKeys = {'Users':[],'Description':'List of users with Key Age greater than (>=) {} days'.format(keyAge),'KeyAgeCutOff':keyAge}

                # print("userName ======"+userName)
                
                key1CreateDate = (accessKeys['AccessKeyMetadata'][0]['CreateDate']).date()

                if (lengthAccessKeyMetadata > 1):
                    oldAccessKey = ''
                    oldAccessKeyStatus = ''

                    key2CreateDate = (accessKeys['AccessKeyMetadata'][1]['CreateDate']).date()    
                    
                    dateDifference = key2CreateDate - key1CreateDate
                    # print("key1CreateDate == "+str(key1CreateDate)+" key2CreateDate == "+str(key2CreateDate)+"****dateDifference  =="+str(dateDifference.days))
                    intDateDifference = int(dateDifference.days)
                    disabledKeyDateDiff = 0
                    if intDateDifference < 0:
                        # dateDifference = key1CreateDate - key2CreateDate
                        # intDateDifference = int(dateDifference.days)

                        disabledKeyDateDiff = date.today() - key1CreateDate

                        newAccessKey = accessKeys['AccessKeyMetadata'][0]['AccessKeyId']
                        oldAccessKey = accessKeys['AccessKeyMetadata'][1]['AccessKeyId']

                        oldAccessKeyStatus = accessKeys['AccessKeyMetadata'][1]['Status']
                    else:
                        # print("********In the else***********")
                        disabledKeyDateDiff = date.today() - key2CreateDate

                        newAccessKey = accessKeys['AccessKeyMetadata'][1]['AccessKeyId']
                        oldAccessKey = accessKeys['AccessKeyMetadata'][0]['AccessKeyId']

                        oldAccessKeyStatus = accessKeys['AccessKeyMetadata'][0]['Status']

                    # print("disabledKeyDateDiff == "+str(disabledKeyDateDiff))
                    disabledKeyDateDiffDays = int(disabledKeyDateDiff.days)
                    # DISABLE: If difference between 2 keys is >= 7 days
                    if (disabledKeyDateDiffDays >= keysDateDifference and oldAccessKeyStatus != "Inactive"):
                        toEmail = setEmail(userName)
                                        
                        print("Disabling Key for user == "+userName)
                        sendKeyDeactivationEmail(userName, newAccessKey, oldAccessKey, toEmail)
                        client.update_access_key(UserName=userName, AccessKeyId=oldAccessKey, Status='Inactive')
                        emailSent = 'true' 
                    elif (disabledKeyDateDiffDays >= deleteKeysDateDifference):
                        toEmail = setEmail(userName)

                        print("Deleting Key for user == "+userName)
                        sendKeyDeletionEmail(userName, newAccessKey, oldAccessKey, toEmail)
                        client.delete_access_key(UserName=userName, AccessKeyId=oldAccessKey)
                        emailSent = 'true' 
                else:
                    # keyAgeDateDifference = date.today() - timedelta(days=int(keyAge))
                    keyAgeDateDifference = date.today() - key1CreateDate
                    createKeyDateDiffDays = int(keyAgeDateDifference.days)

                    # print("timeLimit ="+str(createKeyDateDiffDays) )
                    if createKeyDateDiffDays >= keyAge:
                        # key1CreateDate - 
                        # print("In the eliffffffffffff ++ "+userName)
                        newAccessKey = client.create_access_key(UserName=userName)

                        # Extract just the AccessKey
                        resAccessKey = {key: newAccessKey[key] for key in newAccessKey.keys() 
                                    & {'AccessKey'}}
                        # print ("New Access Key is created "+str(resAccessKey))
                        toEmail = setEmail(userName)

                        ##Creating key
                        print("Creating Key for user == "+userName)
                        message = sendKeyCreationEmail(userName, str(resAccessKey), toEmail) 
                        emailSent = 'true' 

    # print("emailSent == "+emailSent)
    if emailSent == 'false':
        sendAdvisoryEmail()

def setEmail(userName):    
    if (re.search(regex,userName)): 
        if (userName in xyzOrgEmail and pqrSolutionsDomainName in userName):                            
            toEmail = userName.replace("pqrsolutions.com", "xyz.org")    
        elif (userName in pqrSolutionsEmail and xyzOrgDomainName in userName):                            
            toEmail = userName.replace("xyz.org", "pqrsolutions.com")    
        else:
            toEmail = userName
    else:
        toEmail = "infrastructure@xyz.org"

    return toEmail

def sendAdvisoryEmail():    

    message = MIMEMultipart("alternative")
    message["From"] = fromEmail
    
    message["To"] = ccEmail
    message["Cc"] = ccEmail
    message["Subject"] = "IAM Key Rotation ran and all users meet the key criteria"    
    
    # Create the plain-text and HTML version of your message
    html = "<html><body><p>IAM Key Rotation ran and all users meet the key criteria</p></body><html>"

    # Turn these into plain/html MIMEText objects
    # part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    # Add HTML/plain-text parts to MIMEMultipart message
    # message.attach(part1)
    message.attach(part2)

    # Send the message via local SMTP server.
    s = smtplib.SMTP(smtpHost)
    s.sendmail(fromEmail, [ccEmail,ccEmail], message.as_string())
    s.quit()    

    print("**************SENT ADVISORY EMAIL**************")
    
    return message

def sendKeyDeactivationEmail(userName, newAccessKey, oldAccessKey, toEmail):    

    message = MIMEMultipart("alternative")
    message["From"] = fromEmail
    
    message["To"] = toEmail
    message["Cc"] = ccEmail
    message["Subject"] = "Your older AWS Access Key "+oldAccessKey+" is now disabled"    
    
    # Create the plain-text and HTML version of your message
    html = "<html><body><p>Hi " + userName+",<br><br>Your older key "+oldAccessKey+" is 7 days old and is disabled and is marked for deletion and will no longer be available to login. \r\n Please use the new key " + newAccessKey + "<br><br>You can reach out to infrastructure@xyz.org for any issues.</p></body><html>"

    # Turn these into plain/html MIMEText objects
    # part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    # Add HTML/plain-text parts to MIMEMultipart message
    # message.attach(part1)
    message.attach(part2)

    # Send the message via local SMTP server.
    s = smtplib.SMTP(smtpHost)
    s.sendmail(fromEmail, [toEmail,ccEmail], message.as_string())
    s.quit()    

    print("**************SENT KEY DEACTIVATION EMAIL**************")
    
    return message

def sendKeyDeletionEmail(userName, newAccessKey, oldAccessKey, toEmail):   
    
    message = MIMEMultipart("alternative")
    message["From"] = fromEmail
    
    # print("1st key date =="+str(key['CreateDate'])+" 2nd key date == "+str(key2CreateDate))
    message["To"] = toEmail
    message["Cc"] = ccEmail
    message["Subject"] = "Your older AWS Access Key "+oldAccessKey+" is >=30 days and is now deleted."    
    
    # Create the plain-text and HTML version of your message
    html = "<html><body><p>Hi " + userName+",<br><br>Your older key "+oldAccessKey+" is 30 days old and is now deleted. \r\n Please use the new key " + newAccessKey + "<br><br>You can reach out to infrastructure@xyz.org for any issues.</p></body><html>"

    # Turn these into plain/html MIMEText objects
    part2 = MIMEText(html, "html")

    # Add HTML/plain-text parts to MIMEMultipart message
    message.attach(part2)

    # Send the message via local SMTP server.
    s = smtplib.SMTP(smtpHost)
    s.sendmail(fromEmail, [toEmail,ccEmail], message.as_string())
    s.quit()
    print("**************SENT KEY DELETION EMAIL**************")
    return message

def sendKeyCreationEmail(userName, newAccessKey, toEmail):    
    message = MIMEMultipart("alternative")
    message["From"] = fromEmail

    # print("In sendKeyCreationEmail....userName == "+userName+"  toEmail == " +toEmail)
    message["To"] = toEmail
    message["Cc"] = ccEmail
    message["Subject"] = "Your new AWS Access Key"

    # Create the plain-text and HTML version of your message
    html = "<html><body><p>Hi " + userName+",<br><br>New key is created with details.<br><br>" + newAccessKey + "<br><br>Please use the new key as after 7 days the earlier keys will be disabled.</p></body><html>"

    # Turn these into plain/html MIMEText objects
    part2 = MIMEText(html, "html")

    # Add HTML/plain-text parts to MIMEMultipart message
    message.attach(part2)

    # Send the message via local SMTP server.
    s = smtplib.SMTP(smtpHost)
    s.sendmail(fromEmail, [toEmail,ccEmail], message.as_string())
    s.quit()

    print("**************SENT KEY CREATION EMAIL**************")
    
    return message

def lambda_handler(event, context):   
    get_usr_old_keys()
