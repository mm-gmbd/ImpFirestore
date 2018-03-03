#require "promise.class.nut:3.0.1"
#require "AWSLambda.agent.lib.nut:1.0.0"
#require "AWSRequestV4.class.nut:1.0.2"

const FIRESTORE_ID_TOKEN_KIND_RESPONSE              = "identitytoolkit#VerifyCustomTokenResponse";
const FIRESTORE_REFRESH_TOKEN_BEARER_TYPE_RESPONSE  = "Bearer";

class Firestore {
    _projectID      = null;
    _apiKey         = null;
    _customToken    = null;
    _idToken        = null;
    _refreshToken   = null;
    _logLevel       = null;
    _refreshTimer   = null;
    _hasValidToken  = null;
    _defaultHeaders = null;
    _jwtSignKey     = null;
    _signer         = null; //signing service for RS256 encyrption (currently relies on AWS Lambda function named "RSALambda")
    _iss            = null;
    _uid            = null;

    constructor(options) {
        local getIdTokenOnInit;

        //initialize class variables
        this._refreshTimer      = imp.wakeup(0.0, function(){});
        this._hasValidToken     = false;
        this._defaultHeaders    = { "Content-Type": "application/json" };

        //parse options
        this._projectID   = options.projectID;
        this._apiKey      = options.apiKey;
        this._iss         = options.iss;
        this._jwtSignKey  = options.privateKey;
        this._signer      = options.rs256signer;
        this._uid         = "uid"               in options ? options.uid :              split(http.agenturl(), "/")[2],;
        this._logLevel    = "logLevel"          in options ? options.logLevel           : "ERROR";
        getIdTokenOnInit  = "getIdTokenOnInit"  in options ? options.getIdTokenOnInit   : true;

        if (getIdTokenOnInit) {
            this._generateCustomToken()
            .then(function(data){
                return this._getIDAndRefreshToken()
            }.bindenv(this))
            .fail(function(err){
                this._log("Error getting ID and Refresh Tokens: "+err, "constructor", "ERROR");
            }.bindenv(this))
        }
    }

    function isAuthenticated() {
        return this._hasValidToken;
    }

    function read(basicPath) {
        return Promise(function(resolve, reject){
            local path;
            local request;

            if (!this._hasValidToken) {
                reject("No valid token");
            }

            path = this._buildUrl(basicPath);
            request = http.get(path, this._defaultHeaders);
            request.setvalidation(VALIDATE_USING_SYSTEM_CA_CERTS);

            this._processResponse(request)
            .then(function(data){
                resolve(data);
            }.bindenv(this))
            .fail(function(err){
                this._log("Error reading from path ("+basicPath+"): "+err, "read");
                reject(err);
            }.bindenv(this))
        }.bindenv(this));
    }

    function _buildUrl(path, database="(default)", documentOrIndex="documents") {
        return format("https://firestore.googleapis.com/v1beta1/projects/%s/databases/%s/%s/%s/",this._projectID, database, documentOrIndex, path)
    }

    function _generateCustomToken() {
        return Promise(function(resolve, reject){
            local header;
            local claimset;
            local body;
            local signrequest;
            local invokeRequest;

            header = this._urlsafe(http.base64encode("{\"alg\":\"RS256\",\"typ\":\"JWT\"}"));
            claimset = { //
                "iss"   : this._iss,
                "sub"   : this._iss,
                "aud"   : "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
                "exp"   : (time() + 60),
                "iat"   : time()
                "uid"   : this._uid
            };
            body = this._urlsafe(http.base64encode(http.jsonencode(claimset)));
            signrequest = { "privatekey" : this._jwtSignKey, "message"    : header + "." + body };
            invokeRequest = { "payload": signrequest, "functionName": "RSALambda" }

            this._signer.invoke(invokeRequest, function(result){
                if (result.statuscode == 200) {
                    local payload = http.jsondecode(result.body);
                    if ("errorMessage" in payload) {
                        this._log("Error with rs256 sign invocation: "+payload.errorMessage, "_generateCustomToken", "ERROR")
                        reject(payload.errorMessage);
                    } else {
                        // We got the signature, build the OAuth request
                        local signature = this._urlsafe(payload.signature);
                        this._customToken = header+"."+body+"."+signature;
                        resolve(true);
                    }
                } else {
                    // Work around the curl 56 by immediately retrying
                    if (result.statuscode == 56) {
                        this._log("Retrying due to CURL 56", "_generateCustomToken");
                        this._generateCustomToken()
                        .then(resolve.bindenv(this))
                        .fail(reject.bindenv(this))
                    } else {
                        local err = "Lambda returned code "+result.statuscode;
                        this._log(err, "_generateCustomToken", "ERROR");
                        reject(err)
                    }
                }
            }.bindenv(this))
        }.bindenv(this))
    }

    function _getIDAndRefreshToken(){
        return Promise(function(resolve, reject){
            local path = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key="+this._apiKey;
            local body = {"token": this._customToken, "returnSecureToken": true}
            local request = http.post(path, this._defaultHeaders, http.jsonencode(body))

            request.setvalidation(VALIDATE_USING_SYSTEM_CA_CERTS);
            this._processResponse(request)
            .then(function(data){
                local kind = data.kind;
                local idToken = data.idToken;
                local refreshToken = data.refreshToken;
                local expiresIn = data.expiresIn;

                //validate the response
                if (kind != FIRESTORE_ID_TOKEN_KIND_RESPONSE) {
                    throw "'kind' attiribute in response did not match expected response value ("+FIRESTORE_ID_TOKEN_KIND_RESPONSE+")"
                }

                if (typeof expiresIn != "integer") {
                    expiresIn = expiresIn.tointeger();
                }

                this._idToken = idToken;
                this._refreshToken = refreshToken;
                this._hasValidToken = true;
                this._setExpirationTimer(expiresIn);

                resolve(data);
            }.bindenv(this))
            .fail(function(err){
                reject(err);
            }.bindenv(this))
        }.bindenv(this));
    }

    function _getIDTokenFromRefreshToken(){
        return Promise(function(resolve, reject){
            local path = "https://securetoken.googleapis.com/v1/token?key="+this._apiKey;
            local body = {"grant_type": "refresh_token", "refresh_token": this._refreshToken};
            local request = http.post(_buildUrl(path), this._defaultHeaders, http.jsonencode(body))

            request.setvalidation(VALIDATE_USING_SYSTEM_CA_CERTS);
            this._processResponse(request)
            .then(function(data){
                local idToken       = data.idToken;
                local refreshToken  = data.refreshToken;
                local expiresIn     = data.expiresIn;
                local tokenType     = data.tokenType;
                local uid           = data.user_id;     //do we need this? or to validate this?
                local projectId     = data.project_id;  //do we need this? or to validate this?

                //validate the response
                if (tokenType != FIRESTORE_REFRESH_TOKEN_BEARER_TYPE_RESPONSE) {
                    throw "'token_type' attiribute in response did not match expected response value ("+FIRESTORE_REFRESH_TOKEN_BEARER_TYPE_RESPONSE+")"
                }

                if (typeof expiresIn != "integer") {
                    expiresIn = expiresIn.tointeger();
                }

                this._idToken = idToken;
                this._refreshToken = refreshToken;
                this._hasValidToken = true;
                this._setExpirationTimer(expiresIn);

                resolve(data);
            }.bindenv(this))
            .fail(function(err){
                this._log("Error getting ID and Refresh Tokens: "+err, "_getIDTokenFromRefreshToken", "ERROR");

                //TODO: Need to handle error where the custom token has expired
                //if err == custom_token_invalid
                //  return this._generateCustomToken().then(this._getIDAndRefreshToken())
                //else
                //  reject

                reject(err);
            }.bindenv(this))
        }.bindenv(this))
    }

    function _setExpirationTimer(expiresIn) {
        imp.cancelwakeup(this._refreshTimer);
        this._refreshTimer = imp.wakeup(expiresIn, function(){
            this._hasValidToken = false;
            this._log("ID Token expired, requesting new ID Token...", "_setExpirationTimer");
            this._getIDTokenFromRefreshToken()
        }.bindenv(this))
    }

    // return a Promise
    function _createRequestPromise(request) {
        return Promise(function (resolve, reject) {
            request.sendasync(this._createResponseHandler(resolve, reject).bindenv(this));
        }.bindenv(this));
    }

    function _createResponseHandler(onSuccess, onError) {
        return function (res) {
            local response  = res.body;
            local data 
            local error

            try {

                //TODO: Update to check content-type header before trying to decode JSON
                if (response && response.len() > 0) {
                    data = http.jsondecode(response);
                }

                if (200 <= res.statuscode && res.statuscode < 300) {
                    onSuccess(data);
                } else if (res.statuscode == 28 || res.statuscode == 429 || res.statuscode == 503) {
                    onError("Error " + res.statuscode);
                } else if (typeof data == "table" && "error" in data) {
                    error = data ? data.error : null;
                    onError(error);
                } else {
                    onError("Error " + res.statuscode);
                }

            } catch (err) {
                onError(err);
            }
        }
    }

    //TODO: The below was snagged from the Electric Imp Firebase class. Implement eventually...
    // function _createResponseHandler(onSuccess, onError) {
    //     return function (res) {
    //         local response = res.body;
    //         try {
    //             local data = null;
    //             if (response && response.len() > 0) {
    //                 data = http.jsondecode(response);
    //             }
    //             if (200 <= res.statuscode && res.statuscode < 300) {
    //                 onSuccess(data);
    //                 _tooManyReqTimer = false;
    //             } else if (res.statuscode == 28 || res.statuscode == 429 || res.statuscode == 503) {
    //                 local now = time();
    //                 // Too many requests, set _tooManyReqTimer to prevent more requests to FB
    //                 if (_tooManyReqTimer == false) {
    //                     // This is the first 429 we have seen set a default timeout
    //                     _tooManyReqTimer = now + FB_DEFAULT_BACK_OFF_TIMEOUT_SEC;
    //                 } else if (_tooManyReqTimer <= now) {
    //                     // Firebase is still overwhelmed after first timeout expired,
    //                     // Let's block requests for longer to let FB recover
    //                     _tooManyReqTimer = now + (FB_DEFAULT_BACK_OFF_TIMEOUT_SEC * _tooManyReqCounter++);
    //                 }
    //                 // Pass error to callback
    //                 onError("Error " + res.statuscode);
    //             } else if (typeof data == "table" && "error" in data) {
    //                 _tooManyReqTimer = false;
    //                 local error = data ? data.error : null;
    //                 onError(error);
    //             } else {
    //                 _tooManyReqTimer = false;
    //                 onError("Error " + res.statuscode);
    //             }
    //         } catch (err) {
    //             _tooManyReqTimer = false;
    //             onError(err);
    //         }
    //     }
    // }

    function _processResponse(request) {
        local now = time();

        return this._createRequestPromise(request);

        //TODO: The below was snagged from the Electric Imp Firebase class. Implement eventually...

        // // Only send request if we haven't received a 429 error recently
        // if (_tooManyReqTimer == false || _tooManyReqTimer <= now) {
        //     return (usePromise) ? _createRequestPromise(request) : _sendRequest(request, callback);
        // } else {
        //     local error = "ERROR: Too many requests to Firebase, try request again in " + (_tooManyReqTimer - now) + " seconds.";
        //     if (usePromise) {
        //         return Promise.reject(error);
        //     } else {
        //         callback(error, null);
        //     }
        // }
    }

    // Make already base64 encoded string URL safe
    function _urlsafe(s) {
        // Replace "+" with "-" and "/" with "_"
        while(1) {
            local p = s.find("+");
            if (p == null) break;
            s = s.slice(0,p) + "-" + s.slice(p+1);
        }
        while(1) {
            local p = s.find("/");
            if (p == null) break;
            s = s.slice(0,p) + "_" + s.slice(p+1);
        }
        return s;
    }

    function _log(str, src, level="DEBUG") {
        local log = false;
        local logFunc = (level == "ERROR" ? server.error.bindenv(server) : server.log.bindenv(server));

        if (this._logLevel == "DEBUG" || level == "ERROR" || this._logLevel == level) {
            log = true;
        }

        if (log) {
            logFunc("[Firestore]["+src+"]["+level+"]"+str);
        }
    }
}