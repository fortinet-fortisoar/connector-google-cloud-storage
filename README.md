# connector-google-cloud-storage

Google Cloud Storage integration to manage files, buckets, bucket objects, and bucket policies. This integration was integrated with API version v1 of Google Cloud Storage.

# API Documentation Link: https://cloud.google.com/storage/docs/json_api/v1

# Connector Authentication:

You can get authentication token to access the Google Cloud Storage APIs using OAuth 2.0 method.

Please refer https://developers.google.com/identity/protocols/oauth2/web-server for more info

1.	Make sure before using below steps you should create PROJECT in Google Cloud Platform under Web Application to get CLIENT_ID, SECRET_ID and REDIRECT_URI. Please refer https://developers.google.com/adwords/api/docs/guides/authentication#webapp
2.	Under PROJECT enable Cloud Storage API in APIs and Services. Please refer https://support.google.com/googleapi/answer/6158841?hl=en&ref_topic=7013279
3.	Copy the following URL and replace the CLIENT_ID, REDIRECT_URI with your own client ID and redirect URI, accordingly.  https://accounts.google.com/o/oauth2/v2/auth?scope=https://www.googleapis.com/auth/cloud-platform https://accounts.google.com/o/oauth2/v2/auth?scope=https://www.googleapis.com/auth/cloud-platform&access_type=offline&include_granted_scopes=true&response_type=code&state=state_parameter_passthrough_value&redirect_uri=REDIRECT_URI&client_id=CLIENT_ID
4.	Enter the link and you will be prompted to grant permissions for your Cloud Pub/Sub. You will be automatically redirected to a link with the following structure: REDIRECT_URI?state=STATE&code=AUTH_CODE&scope=SCOPE
5.	Copy the AUTH_CODE (without the "code=" prefix) and paste it in your instance configuration under the Authorization code parameter.
6.	Enter your client ID in the Client ID parameter field.
7.	Enter your client secret in the Client Secret parameter field.
8.	Enter your redirect URI in the Redirect URI parameter field.
