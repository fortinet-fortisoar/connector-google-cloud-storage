""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from requests import request, exceptions as req_exceptions
from .google_api_auth import *

SCOPES = ['https://www.googleapis.com/auth/cloud-platform']
STORAGE_API = 'storage/v1'

logger = get_logger('google-cloud-storage')

bucket_projection = {
    'All Properties': 'full',
    'Default Properties': 'noAcl'
}

bucket_access_control = {
    'Authenticated Read': 'authenticatedRead',
    'Private': 'private',
    'Project Private': 'projectPrivate',
    'Public Read': 'publicRead',
    'Public ReadWrite': 'publicReadWrite'
}

bucket_default_access_control = {
    'Authenticated Read': 'authenticatedRead',
    'Bucket Owner FullControl': 'bucketOwnerFullControl',
    'Bucket Owner Read': 'bucketOwnerRead',
    'Private': 'private',
    'Project Private': 'projectPrivate',
    'Public Read': 'publicRead'
}


def api_request(method, endpoint, connector_info, config, params=None, data=None, headers={}):
    try:
        go = GoogleAuth(config)
        endpoint = go.host + "/" + endpoint
        token = go.validate_token(config, connector_info)
        headers['Authorization'] = token
        headers['Content-Type'] = 'application/json'
        logger.debug("Endpoint: {0}".format(endpoint))
        try:
            response = request(method, endpoint, headers=headers, params=params, json=data, verify=go.verify_ssl)
            logger.debug("Response Status Code: {0}".format(response.status_code))
            logger.debug("Response: {0}".format(response.text))
            logger.debug("API Header: {0}".format(response.headers))
            if response.status_code in [200, 201, 204]:
                if response.text != "":
                    return response.json()
                else:
                    return True
            else:
                if response.text != "":
                    err_resp = response.json()
                    failure_msg = err_resp['error']['message']
                    error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason,
                                                                         failure_msg if failure_msg else '')
                else:
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
                logger.error(error_msg)
                raise ConnectorError(error_msg)
        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            raise ConnectorError(str(err))
    except Exception as err:
        raise ConnectorError(str(err))


def check_payload(payload):
    payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    return payload


def create_bucket(config, params, connector_info):
    try:
        url = '{0}/b'.format(STORAGE_API)
        projection = params.get('projection')
        additional_fields = params.get('additional_fields')
        if projection:
            projection = bucket_projection.get(projection)
        predefinedAcl = params.get('predefinedAcl')
        if predefinedAcl:
            predefinedAcl = bucket_access_control.get(predefinedAcl)
        predefinedDefaultObjectAcl = params.get('predefinedDefaultObjectAcl')
        if predefinedDefaultObjectAcl:
            predefinedDefaultObjectAcl = bucket_default_access_control.get(predefinedDefaultObjectAcl)
        query_parameter = {
            'project': params.get('project'),
            'predefinedAcl': predefinedAcl,
            'predefinedDefaultObjectAcl': predefinedDefaultObjectAcl,
            'projection': projection
        }
        payload = {
            'name': params.get('bucket')
        }
        if additional_fields:
            payload.update(additional_fields)
        query_parameter = check_payload(query_parameter)
        payload = check_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = api_request('POST', url, connector_info, config, params=query_parameter, data=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_buckets_list(config, params, connector_info):
    try:
        url = '{0}/b'.format(STORAGE_API)
        projection = params.get('projection')
        if projection:
            projection = bucket_projection.get(projection)
        payload = {
            'project': params.get('project'),
            'maxResults': params.get('maxResults'),
            'pageToken': params.get('pageToken'),
            'prefix': params.get('prefix'),
            'projection': projection
        }
        payload = check_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = api_request('GET', url, connector_info, config, params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_bucket_details(config, params, connector_info):
    try:
        url = '{0}/b/{1}'.format(STORAGE_API, params.get('bucket'))
        projection = params.get('projection')
        if projection:
            projection = bucket_projection.get(projection)
        payload = {
            'ifMetagenerationMatch': params.get('ifMetagenerationMatch'),
            'ifMetagenerationNotMatch': params.get('ifMetagenerationNotMatch'),
            'projection': projection
        }
        payload = check_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = api_request('GET', url, connector_info, config, params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def delete_bucket(config, params, connector_info):
    try:
        url = '{0}/b/{1}'.format(STORAGE_API, params.get('bucket'))
        payload = {
            'ifMetagenerationMatch': params.get('ifMetagenerationMatch'),
            'ifMetagenerationNotMatch': params.get('ifMetagenerationNotMatch')
        }
        payload = check_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = api_request('DELETE', url, connector_info, config, params=payload)
        return {"result": "Deleted bucket {0} successfully".format(params.get('bucket'))}
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def create_bucket_policy(config, params, connector_info):
    try:
        url = '{0}/b/{1}/acl'.format(STORAGE_API, params.get('bucket'))
        additional_fields = params.get('additional_fields')
        payload = {
            'entity': params.get('entity'),
            'role': params.get('role')
        }
        if additional_fields:
            payload.update(additional_fields)
        payload = check_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = api_request('POST', url, connector_info, config, data=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_buckets_list_policy(config, params, connector_info):
    try:
        url = '{0}/b/{1}/acl'.format(STORAGE_API, params.get('bucket'))
        response = api_request('GET', url, connector_info, config)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_bucket_policy_details(config, params, connector_info):
    try:
        url = '{0}/b/{1}/acl/{2}'.format(STORAGE_API, params.get('bucket'), params.get('entity'))
        response = api_request('GET', url, connector_info, config)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def update_bucket_policy(config, params, connector_info):
    try:
        url = '{0}/b/{1}/acl/{2}'.format(STORAGE_API, params.get('bucket'), params.get('entity'))
        additional_fields = params.get('additional_fields')
        payload = {
            'role': params.get('role')
        }
        if additional_fields:
            payload.update(additional_fields)
        payload = check_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = api_request('PUT', url, connector_info, config, data=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def delete_bucket_policy(config, params, connector_info):
    try:
        url = '{0}/b/{1}/acl/{2}'.format(STORAGE_API, params.get('bucket'), params.get('entity'))
        response = api_request('DELETE', url, connector_info, config)
        return {"result": "Deleted bucket {0} policy successfully".format(params.get('bucket'))}
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def create_bucket_object_policy(config, params, connector_info):
    try:
        url = '{0}/b/{1}/o/{2}/acl'.format(STORAGE_API, params.get('bucket'), params.get('object'))
        payload = {
            'entity': params.get('entity'),
            'role': params.get('role')
        }
        query_parameter = {
            'generation': params.get('generation')
        }
        payload = check_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = api_request('POST', url, connector_info, config, data=payload, params=query_parameter)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_buckets_list_object_policy(config, params, connector_info):
    try:
        url = '{0}/b/{1}/o/{2}/acl'.format(STORAGE_API, params.get('bucket'), params.get('object'))
        payload = {
            'generation': params.get('generation')
        }
        payload = check_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = api_request('GET', url, connector_info, config, params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_bucket_object_policy_details(config, params, connector_info):
    try:
        url = '{0}/b/{1}/o/{2}/acl/{3}'.format(STORAGE_API, params.get('bucket'), params.get('object'),
                                               params.get('entity'))
        payload = {
            'generation': params.get('generation')
        }
        payload = check_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = api_request('GET', url, connector_info, config, params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def update_bucket_object_policy(config, params, connector_info):
    try:
        url = '{0}/b/{1}/o/{2}/acl/{3}'.format(STORAGE_API, params.get('bucket'), params.get('object'),
                                               params.get('entity'))
        query_parameter = {
            'generation': params.get('generation')
        }
        additional_fields = params.get('additional_fields')
        payload = {
            'role': params.get('role')
        }
        if additional_fields:
            payload.update(additional_fields)
        payload = check_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = api_request('PUT', url, connector_info, config, params=query_parameter, data=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def delete_bucket_object_policy(config, params, connector_info):
    try:
        url = '{0}/b/{1}/o/{2}/acl/{3}'.format(STORAGE_API, params.get('bucket'), params.get('object'),
                                               params.get('entity'))
        payload = {
            'generation': params.get('generation')
        }
        payload = check_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = api_request('DELETE', url, connector_info, config, params=payload)
        return {"result": "Deleted bucket {0} object policy successfully".format(params.get('bucket'))}
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def _check_health(config, connector_info):
    try:
        return check(config, connector_info)
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'create_bucket': create_bucket,
    'get_buckets_list': get_buckets_list,
    'get_bucket_details': get_bucket_details,
    'delete_bucket': delete_bucket,
    'create_bucket_policy': create_bucket_policy,
    'get_buckets_list_policy': get_buckets_list_policy,
    'get_bucket_policy_details': get_bucket_policy_details,
    'update_bucket_policy': update_bucket_policy,
    'delete_bucket_policy': delete_bucket_policy,
    'create_bucket_object_policy': create_bucket_object_policy,
    'get_buckets_list_object_policy': get_buckets_list_object_policy,
    'get_bucket_object_policy_details': get_bucket_object_policy_details,
    'update_bucket_object_policy': update_bucket_object_policy,
    'delete_bucket_object_policy': delete_bucket_object_policy

}
