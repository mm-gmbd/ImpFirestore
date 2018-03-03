# Firestore

Library for interacting with [Google Firestore](https://firebase.google.com/docs/firestore/)
using the [Electric Imp](https://electricimp.com/) platform.

As specified in the Firestore documentation, this library utilizes both the 
[Firestore REST API](https://firebase.google.com/docs/firestore/use-rest-api) and the 
[Firebase Auth REST API](https://firebase.google.com/docs/reference/rest/auth/).

The Agent must authenticate itself to the Firestore REST API one of two ways:

- Firebase Authentication ID Token
- Google Identity OAuth 2.0 Token

Currently, this library only supports the use of the Firebase Authentication ID Token for
making Firestore REST requests.

# Methods

## constructor

### Method Parameters

| Parameter        | Type      | Required   | Description | Default |
| ---------------- | --------- | ---------- | ----------- | ------- |
| projectID        | string    | Required   | The Firestore project ID | | 
| apiKey           | string    | Required   | The application ID the Agent will use to access the Firestore project | |
| clientEmail      | string    | Required   | The service account email address |
| privateKey       | string    | Required   | RSA256 Private Key for creating the Custom Token | |
| rs256Signer      | AWSLambda | Required   | AWS Lambda Function to invoke to sign the Custom Token | |
| uid              | string    | Optional   | The user identifier | Electric Imp Agent ID |
| logLevel         | string    | Optional   | Supported log levels are `"DEBUG"` and `"ERROR"` and are used for controlling the level of output from the class | `"ERROR"` | 
| getIdTokenOnInit | boolean   | Optional   | If `true`, on construction of the class, an attempt will be made to generate a custom token and get an ID and refresh token, otherwise the class will lazily perform these functions as necessary | `true` |

## isAuthenticated

### Method Parameters

This method accepts no parameters.

### Return Value

| Type    | Description                                |
| ------- | ------------------------------------------ |
| boolean | `true` if authenticated, `false` otherwise |

## read

### Method Parameters

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| path      | string | Required | The path to read from |

### Return Value

| Type    | Description                                |
| ------- | ------------------------------------------ |
| Promise | If the read is successful, the Promise will `resolve` with the data from the read. Otherwise, it will `reject` with an error object. |


## write

NOT IMPLEMENTED.

### Method Parameters

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
|           |      |          |             |

## update

NOT IMPLEMENTED.

### Method Parameters

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
|           |      |          |             |

## delete

NOT IMPLEMENTED.

### Method Parameters

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
|           |      |          |             |
