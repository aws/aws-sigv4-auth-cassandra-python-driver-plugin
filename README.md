# IMPORTANT: Latest Version

The current version is 4.0.2. Please see the [changelog](./CHANGELOG.md) for details on version history.

# What

This package implements an authentication plugin for the open-source Datastax Python Driver for Apache Cassandra. 
The driver enables you to add authentication information to your API requests using the AWS Signature Version 4 Process (SigV4). 
Using the plugin, you can provide users and applications short-term credentials to access Amazon Keyspaces (for Apache Cassandra) 
using AWS Identity and Access Management (IAM) users and roles.

The plugin depends on the AWS SDK for Python (Boto3). It uses `boto3.Session` to obtain credentials. 


# Example Usage

``` python
ssl_context = SSLContext(PROTOCOL_TLSv1_2)
ssl_context.load_verify_locations('./AmazonRootCA1.pem')
ssl_context.verify_mode = CERT_REQUIRED
boto_session = boto3.Session(aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
                             aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                             aws_session_token="AQoDYXdzEJr...<remainder of token>",
                             region_name="us-east-2")
auth_provider = SigV4AuthProvider(boto_session)
cluster = Cluster(['cassandra.us-east-2.amazonaws.com'], ssl_context=ssl_context, auth_provider=auth_provider,
                  port=9142)
session = cluster.connect()
r = session.execute('select * from system_schema.keyspaces')
print(r.current_rows)
```

# Using the Plugin

The following sections describe how to use the authentication plugin for the open-source DataStax Python Driver for Cassandra to access Amazon Keyspaces.

## SSL Configuration

The first step is to get an Amazon digital certificate to encrypt your connections using Transport Layer Security (TLS).
The DataStax Python driver must use an SSL CA certificate so that the client SSL engine can validate the Amazon Keyspaces 
certificate on connection.

``` python
ssl_context = SSLContext(PROTOCOL_TLSv1_2)
ssl_context.load_verify_locations('./AmazonRootCA1.pem')
ssl_context.verify_mode = CERT_REQUIRED
```

## Region Configuration

Before you can start using the plugin, you must configure the AWS Region that the plugin will use when authenticating.
This is required because SigV4 signatures are Region-specific. For example, if you are connecting to the `cassandra.us-east-2.amazonaws.com` endpoint,
the Region must be `us-east-2`. For a list of available AWS Regions and endpoints, see [Service Endpoints for Amazon Keyspaces](https://docs.aws.amazon.com/keyspaces/latest/devguide/programmatic.endpoints.html).

You can specify the Region using one of the following four methods:

* Environment Variable
* Constructor
* Boto3 Session Configuration

## Environment Variable

You can use the `AWS_REGION` environment variable to match the endpoint that you are 
communicating with by setting it as part of your application start-up, as follows.

``` shell
$ export AWS_REGION=us-east-2
```

## Constructor

You can either provide the constructor for `SigV4AuthProvider` with a boto3 session, aws credentials and a region,
or a parameterless constructor to follow the default boto3 credential discovery path.

## Install the plugin in your environment

``` shell
pip install cassandra-sigv4
```

## Programmatically Configure the Driver With a boto3 session

Note that if a session is provided, all other arguments for the constructor are ignored.

``` python
boto_session = boto3.Session(aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
                             aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                             aws_session_token="AQoDYXdzEJr...<remainder of token>",
                             region_name="us-east-2")
auth_provider = SigV4AuthProvider(boto_session)
cluster = Cluster(['cassandra.us-east-2.amazonaws.com'], ssl_context=ssl_context, auth_provider=auth_provider,
                  port=9142)
```

## Programmatically Configure the Drive with raw AWS Credentials

``` python
auth_provider = SigV4AuthProvider(aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
                                  aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                                  aws_session_token="AQoDYXdzEJr...<remainder of token>",
                                  region_name="us-east-2")
cluster = Cluster(['cassandra.us-east-2.amazonaws.com'], ssl_context=ssl_context, auth_provider=auth_provider,
                  port=9142)
```
