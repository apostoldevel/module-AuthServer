/*++

Program name:

  Apostol Web Service

Module Name:

  AuthServer.cpp

Notices:

  Module: OAuth 2 Authorization Server

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

//----------------------------------------------------------------------------------------------------------------------

#include "Core.hpp"
#include "AuthServer.hpp"
//----------------------------------------------------------------------------------------------------------------------

#include "jwt.h"
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Workers {

        //--------------------------------------------------------------------------------------------------------------

        //-- CAuthServer -----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CAuthServer::CAuthServer(CModuleProcess *AProcess) : CApostolModule(AProcess, "authorization server") {
            m_Headers.Add("Authorization");

            m_FixedDate = Now();

            CAuthServer::InitMethods();
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::InitMethods() {
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            m_pMethods->AddObject(_T("GET")    , (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoGet(Connection); }));
            m_pMethods->AddObject(_T("POST")   , (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoPost(Connection); }));
            m_pMethods->AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
#else
            m_pMethods->AddObject(_T("GET")    , (CObject *) new CMethodHandler(true, std::bind(&CAuthServer::DoGet, this, _1)));
            m_pMethods->AddObject(_T("POST")   , (CObject *) new CMethodHandler(true, std::bind(&CAuthServer::DoPost, this, _1)));
            m_pMethods->AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, std::bind(&CAuthServer::MethodNotAllowed, this, _1)));
#endif
        }
        //--------------------------------------------------------------------------------------------------------------

        CReply::CStatusType CAuthServer::ErrorCodeToStatus(int ErrorCode) {
            CReply::CStatusType Status = CReply::ok;

            if (ErrorCode != 0) {
                switch (ErrorCode) {
                    case 401:
                        Status = CReply::unauthorized;
                        break;

                    case 403:
                        Status = CReply::forbidden;
                        break;

                    case 404:
                        Status = CReply::not_found;
                        break;

                    case 500:
                        Status = CReply::internal_server_error;
                        break;

                    default:
                        Status = CReply::bad_request;
                        break;
                }
            }

            return Status;
        }
        //--------------------------------------------------------------------------------------------------------------

        int CAuthServer::CheckError(const CJSON &Json, CString &ErrorMessage, bool RaiseIfError) {
            int ErrorCode = 0;

            if (Json.HasOwnProperty(_T("error"))) {
                const auto& error = Json[_T("error")];

                if (error.HasOwnProperty(_T("code"))) {
                    ErrorCode = error[_T("code")].AsInteger();
                } else {
                    ErrorCode = 40000;
                }

                if (error.HasOwnProperty(_T("message"))) {
                    ErrorMessage = error[_T("message")].AsString();
                } else {
                    ErrorMessage = _T("Invalid request.");
                }

                if (RaiseIfError)
                    throw EDBError(ErrorMessage.c_str());

                if (ErrorCode >= 10000)
                    ErrorCode = ErrorCode / 100;
            }

            return ErrorCode;
        }
        //--------------------------------------------------------------------------------------------------------------

        int CAuthServer::CheckOAuth2Error(const CJSON &Json, CString &Error, CString &ErrorDescription) {
            int ErrorCode = 0;

            if (Json.HasOwnProperty(_T("error"))) {
                const auto& error = Json[_T("error")];

                if (error.HasOwnProperty(_T("code"))) {
                    ErrorCode = error[_T("code")].AsInteger();
                } else {
                    ErrorCode = 400;
                }

                if (error.HasOwnProperty(_T("error"))) {
                    Error = error[_T("error")].AsString();
                } else {
                    Error = _T("invalid_request");
                }

                if (error.HasOwnProperty(_T("message"))) {
                    ErrorDescription = error[_T("message")].AsString();
                } else {
                    ErrorDescription = _T("Invalid request.");
                }
            }

            return ErrorCode;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::AfterQuery(CHTTPServerConnection *AConnection, const CString &Path, const CJSON &Payload) {
            if (Path == _T("/sign/in/token")) {
                SetAuthorizationData(AConnection, Payload);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::DoPostgresQueryExecuted(CPQPollQuery *APollQuery) {
            clock_t start = clock();

            auto LResult = APollQuery->Results(0);

            if (LResult->ExecStatus() != PGRES_TUPLES_OK) {
                QueryException(APollQuery, Delphi::Exception::EDBError(LResult->GetErrorMessage()));
                return;
            }

            CString ErrorMessage;

            auto LConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->PollConnection());

            if (LConnection != nullptr) {

                const auto& Path = LConnection->Data()["path"].Lower();

                auto LRequest = LConnection->Request();
                auto LReply = LConnection->Reply();

                const auto& result_object = LRequest->Params[_T("result_object")];
                const auto& data_array = LRequest->Params[_T("data_array")];

                CReply::CStatusType LStatus = CReply::ok;

                try {
                    if (LResult->nTuples() == 1) {
                        const CJSON Payload(LResult->GetValue(0, 0));
                        LStatus = ErrorCodeToStatus(CheckError(Payload, ErrorMessage));
                        if (LStatus == CReply::ok) {
                            AfterQuery(LConnection, Path, Payload);
                        }
                    }

                    PQResultToJson(LResult, LReply->Content);
                } catch (Delphi::Exception::Exception &E) {
                    ErrorMessage = E.what();
                    LStatus = CReply::bad_request;
                    Log()->Error(APP_LOG_EMERG, 0, E.what());
                }

                const auto& LRedirect = LStatus == CReply::ok ? LConnection->Data()["redirect"] : LConnection->Data()["redirect_error"];

                if (LRedirect.IsEmpty()) {
                    if (LStatus == CReply::ok) {
                        LConnection->SendReply(LStatus, nullptr, true);
                    } else {
                        ReplyError(LConnection, LStatus, "server_error", ErrorMessage);
                    }
                } else {
                    if (LStatus == CReply::ok) {
                        Redirect(LConnection, LRedirect, true);
                    } else {
                        switch (LStatus) {
                            case CReply::unauthorized:
                                RedirectError(LConnection, LRedirect, LStatus, "unauthorized_client", ErrorMessage);
                                break;

                            case CReply::forbidden:
                                RedirectError(LConnection, LRedirect, LStatus, "access_denied", ErrorMessage);
                                break;

                            case CReply::internal_server_error:
                                RedirectError(LConnection, LRedirect, LStatus, "server_error", ErrorMessage);
                                break;

                            default:
                                RedirectError(LConnection, LRedirect, LStatus, "invalid_request", ErrorMessage);
                                break;
                        }
                    }
                }
            }

            log_debug1(APP_LOG_DEBUG_CORE, Log(), 0, _T("Query executed runtime: %.2f ms."), (double) ((clock() - start) / (double) CLOCKS_PER_SEC * 1000));
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::QueryException(CPQPollQuery *APollQuery, const std::exception &e) {

            auto LConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->PollConnection());

            if (LConnection != nullptr) {
                auto LReply = LConnection->Reply();

                const auto& LRedirect = LConnection->Data()["redirect_error"];

                if (!LRedirect.IsEmpty()) {
                    RedirectError(LConnection, LRedirect, CReply::internal_server_error, "server_error", e.what());
                } else {
                    ExceptionToJson(CReply::internal_server_error, e, LReply->Content);
                    LConnection->SendReply(CReply::ok, nullptr, true);
                }
            }

            Log()->Error(APP_LOG_EMERG, 0, e.what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::DoPostgresQueryException(CPQPollQuery *APollQuery, Delphi::Exception::Exception *AException) {
            QueryException(APollQuery, *AException);
        }
        //--------------------------------------------------------------------------------------------------------------

        CString CAuthServer::CreateToken(const CCleanToken& CleanToken) {
            const auto& Providers = Server().Providers();
            const auto& Default = Providers.Default().Value();

            auto token = jwt::create()
                    .set_issuer(Default.Issuer("web"))
                    .set_audience(Default.ClientId("web"))
                    .set_issued_at(std::chrono::system_clock::now())
                    .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{3600})
                    .sign(jwt::algorithm::hs256{std::string(Default.Secret("web"))});

            return token;
        }
        //--------------------------------------------------------------------------------------------------------------

        CString CAuthServer::VerifyToken(const CString &Token) {

            const auto& GetSecret = [](const CProvider &Provider, const CString &Application) {
                const auto &Secret = Provider.Secret(Application);
                if (Secret.IsEmpty())
                    throw ExceptionFrm("Not found Secret for \"%s:%s\"",
                                       Provider.Name.c_str(),
                                       Application.c_str()
                    );
                return Secret;
            };

            auto decoded = jwt::decode(Token);
            const auto& aud = CString(decoded.get_audience());

            CString Application;

            const auto& Providers = Server().Providers();

            const auto Index = OAuth2::Helper::ProviderByClientId(Providers, aud, Application);
            if (Index == -1)
                throw COAuth2Error(_T("Not found provider by Client ID."));

            const auto& Provider = Providers[Index].Value();

            const auto& iss = CString(decoded.get_issuer());
            const CStringList& Issuers = Provider.GetIssuers(Application);
            if (Issuers[iss].IsEmpty())
                throw jwt::token_verification_exception("Token doesn't contain the required issuer.");

            const auto& alg = decoded.get_algorithm();
            const auto& ch = alg.substr(0, 2);

            const auto& Secret = GetSecret(Provider, Application);

            if (ch == "HS") {
                if (alg == "HS256") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::hs256{Secret});
                    verifier.verify(decoded);

                    return Token; // if algorithm HS256
                } else if (alg == "HS384") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::hs384{Secret});
                    verifier.verify(decoded);
                } else if (alg == "HS512") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::hs512{Secret});
                    verifier.verify(decoded);
                }
            } else if (ch == "RS") {

                const auto& kid = decoded.get_key_id();
                const auto& key = OAuth2::Helper::GetPublicKey(Providers, kid);

                if (alg == "RS256") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::rs256{key});
                    verifier.verify(decoded);
                } else if (alg == "RS384") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::rs384{key});
                    verifier.verify(decoded);
                } else if (alg == "RS512") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::rs512{key});
                    verifier.verify(decoded);
                }
            } else if (ch == "ES") {

                const auto& kid = decoded.get_key_id();
                const auto& key = OAuth2::Helper::GetPublicKey(Providers, kid);

                if (alg == "ES256") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::es256{key});
                    verifier.verify(decoded);
                } else if (alg == "ES384") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::es384{key});
                    verifier.verify(decoded);
                } else if (alg == "ES512") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::es512{key});
                    verifier.verify(decoded);
                }
            } else if (ch == "PS") {

                const auto& kid = decoded.get_key_id();
                const auto& key = OAuth2::Helper::GetPublicKey(Providers, kid);

                if (alg == "PS256") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::ps256{key});
                    verifier.verify(decoded);
                } else if (alg == "PS384") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::ps384{key});
                    verifier.verify(decoded);
                } else if (alg == "PS512") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::ps512{key});
                    verifier.verify(decoded);
                }
            }

            const auto& Result = CCleanToken(R"({"alg":"HS256","typ":"JWT"})", decoded.get_payload(), true);

            return Result.Sign(jwt::algorithm::hs256{Secret});
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::LoadCerts() {
            const CString pathCerts = Config()->Prefix() + _T("certs/");
            const CString lockFile = pathCerts + "lock";
            if (!FileExists(lockFile.c_str())) {
                auto& Providers = Server().Providers();
                for (int i = 0; i < Providers.Count(); i++) {
                    auto &Provider = Providers[i].Value();
                    if (FileExists(CString(pathCerts + Provider.Name).c_str())) {
                        Provider.Keys.Clear();
                        Provider.Keys.LoadFromFile(CString(pathCerts + Provider.Name).c_str());
                    }
                }
            } else {
                m_FixedDate = Now() + (CDateTime) 1 / SecsPerDay; // 1 sec
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::Identifier(CHTTPServerConnection *AConnection, const CString &Identifier) {

            auto OnExecuted = [this, AConnection](CPQPollQuery *APollQuery) {

                auto LReply = AConnection->Reply();
                auto LResult = APollQuery->Results(0);

                CString ErrorMessage;
                CReply::CStatusType LStatus = CReply::internal_server_error;

                try {
                    if (LResult->ExecStatus() != PGRES_TUPLES_OK)
                        throw Delphi::Exception::EDBError(LResult->GetErrorMessage());

                    LReply->ContentType = CReply::json;

                    const CJSON Payload(LResult->GetValue(0, 0));
                    LStatus = ErrorCodeToStatus(CheckError(Payload, ErrorMessage));
                    PQResultToJson(LResult, LReply->Content);
                } catch (Delphi::Exception::Exception &E) {
                    LReply->Content.Clear();
                    ExceptionToJson(LStatus, E, LReply->Content);
                    Log()->Error(APP_LOG_EMERG, 0, E.what());
                }

                AConnection->SendReply(LStatus, nullptr, true);
            };

            auto OnException = [this, AConnection](CPQPollQuery *APollQuery, Delphi::Exception::Exception *AException) {

                auto LReply = AConnection->Reply();

                LReply->Content.Clear();
                ExceptionToJson(CReply::internal_server_error, *AException, LReply->Content);
                AConnection->SendStockReply(CReply::ok, true);

                Log()->Error(APP_LOG_EMERG, 0, AException->what());

            };

            CStringList SQL;

            SQL.Add(CString().Format("SELECT * FROM daemon.identifier(%s);", PQQuoteLiteral(Identifier).c_str()));

            if (!ExecSQL(SQL, AConnection, OnExecuted, OnException)) {
                AConnection->SendStockReply(CReply::service_unavailable);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::Authorize(CHTTPServerConnection *AConnection, const CString &Session, const CString &Path,
                                    const CString &Resource) {

            auto OnExecuted = [this, AConnection](CPQPollQuery *APollQuery) {

                auto LReply = AConnection->Reply();

                const auto& LSession = AConnection->Data()["session"];
                const auto& LPath = AConnection->Data()["path"];
                const auto& LResource = AConnection->Data()["resource"];

                CPQResult *Result;
                CStringList SQL;

                try {
                    for (int I = 0; I < APollQuery->Count(); I++) {
                        Result = APollQuery->Results(I);

                        if (Result->ExecStatus() != PGRES_TUPLES_OK)
                            throw Delphi::Exception::EDBError(Result->GetErrorMessage());

                        CString ErrorMessage;

                        const CJSON Payload(Result->GetValue(0, 0));
                        if (CheckError(Payload, ErrorMessage) == 0) {
                            if (LPath == _T("/")) {
                                AConnection->Data().Values("redirect", "/dashboard/");
                                SetAuthorizationData(AConnection, Payload);
                                Redirect(AConnection, AConnection->Data()["redirect"], true);
                            } else {
                                SendResource(AConnection, LResource, _T("text/html"), true);
                            }

                            return;
                        } else {
                            LReply->SetCookie(_T("SID"), _T("null"), _T("/"), -1);

                            if (!ErrorMessage.IsEmpty())
                                Log()->Error(APP_LOG_INFO, 0, ErrorMessage.c_str());
                        }
                    }
                } catch (std::exception &e) {
                    Log()->Error(APP_LOG_EMERG, 0, e.what());
                }

                Redirect(AConnection, _T("/welcome/"),true);
            };

            auto OnException = [this, AConnection](CPQPollQuery *APollQuery, Delphi::Exception::Exception *AException) {

                Log()->Error(APP_LOG_EMERG, 0, AException->what());
                AConnection->SendStockReply(CReply::internal_server_error, true);

            };

            CStringList SQL;

            SQL.Add(CString().Format("SELECT * FROM daemon.authorize('%s');", Session.c_str()));

            AConnection->Data().Values("session", Session);
            AConnection->Data().Values("path", Path);
            AConnection->Data().Values("resource", Resource);

            if (!ExecSQL(SQL, nullptr, OnExecuted, OnException)) {
                AConnection->SendStockReply(CReply::service_unavailable);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::RedirectError(CHTTPServerConnection *AConnection, const CString &Location, int ErrorCode, const CString &Error, const CString &Message) {
            CString ErrorLocation(Location);

            ErrorLocation << "?code=" << ErrorCode;
            ErrorLocation << "&error=" << Error;
            ErrorLocation << "&error_description=" << CHTTPServer::URLEncode(Message);

            Redirect(AConnection, ErrorLocation, true);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::ReplyError(CHTTPServerConnection *AConnection, int ErrorCode, const CString &Error, const CString &Message) {
            auto LReply = AConnection->Reply();

            CReply::CStatusType Status = ErrorCodeToStatus(ErrorCode);

            if (ErrorCode == CReply::unauthorized) {
                CReply::AddUnauthorized(LReply, true, "access_denied", Message.c_str());
            }

            LReply->Content.Clear();
            LReply->Content.Format(R"({"error": "%s", "error_description": "%s"})",
                                   Error.c_str(), Delphi::Json::EncodeJsonString(Message).c_str());

            AConnection->SendReply(Status, nullptr, true);
        };
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::DoToken(CHTTPServerConnection *AConnection) {

            auto OnExecuted = [AConnection, this](CPQPollQuery *APollQuery) {

                auto LReply = AConnection->Reply();
                auto LResult = APollQuery->Results(0);

                CString Error;
                CString ErrorDescription;

                CReply::CStatusType LStatus;

                try {
                    if (LResult->ExecStatus() != PGRES_TUPLES_OK)
                        throw Delphi::Exception::EDBError(LResult->GetErrorMessage());

                    PQResultToJson(LResult, LReply->Content);

                    const CJSON Json(LReply->Content);
                    LStatus = ErrorCodeToStatus(CheckOAuth2Error(Json, Error, ErrorDescription));

                    if (LStatus == CReply::ok) {
                        AConnection->SendReply(LStatus, nullptr, true);
                    } else {
                        ReplyError(AConnection, LStatus, Error, ErrorDescription);
                    }
                } catch (Delphi::Exception::Exception &E) {
                    ReplyError(AConnection, 500, "server_error", E.what());
                    Log()->Error(APP_LOG_EMERG, 0, E.what());
                }
            };

            auto OnException = [AConnection, this](CPQPollQuery *APollQuery, Delphi::Exception::Exception *AException) {
                ReplyError(AConnection, 500, "server_error", *AException->what());
                Log()->Error(APP_LOG_EMERG, 0, AException->what());
            };

            auto LRequest = AConnection->Request();
            auto LReply = AConnection->Reply();

            CJSON Json;
            ContentToJson(LRequest, Json);

            const auto &client_id = Json["client_id"].AsString();
            const auto &client_secret = Json["client_secret"].AsString();
            const auto &grant_type = Json["grant_type"].AsString();
            const auto &redirect_uri = Json["redirect_uri"].AsString();

            CAuthorization Authorization;
            const auto &LAuthorization = LRequest->Headers.Values(_T("Authorization"));

            if (LAuthorization.IsEmpty()) {
                const auto &Providers = Server().Providers();

                Authorization.Schema = CAuthorization::asBasic;

                if (client_id.IsEmpty()) {
                    const auto &Provider = Providers.Default().Value();

                    Authorization.Username = Provider.ClientId("web");
                    Authorization.Password = Provider.Secret("web");
                } else {
                    Authorization.Username = client_id;

                    if (client_secret.IsEmpty()) {
                        CString Application;
                        const auto Index = OAuth2::Helper::ProviderByClientId(Providers, client_id, Application);
                        if (Index != -1) {
                            const auto &Provider = Providers[Index].Value();
                            Authorization.Password = Provider.Secret(Application);
                        }
                    } else {
                        Authorization.Password = client_secret;
                    }
                }
            } else {
                Authorization << LAuthorization;

                if (Authorization.Schema != CAuthorization::asBasic) {
                    ReplyError(AConnection, 400, "invalid_request", "Invalid authorization schema.");
                    return;
                }
            }

            const auto &Agent = GetUserAgent(AConnection);
            const auto &Host = GetHost(AConnection);

            CStringList SQL;

            SQL.Add(CString().Format("SELECT * FROM daemon.token(%s, %s, '%s'::jsonb, %s, %s);",
                                     PQQuoteLiteral(Authorization.Username).c_str(),
                                     PQQuoteLiteral(Authorization.Password).c_str(),
                                     Json.ToString().c_str(),
                                     PQQuoteLiteral(Agent).c_str(),
                                     PQQuoteLiteral(Host).c_str()
            ));

            if (!ExecSQL(SQL, AConnection, OnExecuted, OnException)) {
                ReplyError(AConnection, 400, "temporarily_unavailable", "Temporarily unavailable.");
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::SignInToken(CHTTPServerConnection *AConnection, const CJSON &Token) {

            const auto &errorLocation = AConnection->Data()["redirect_error"];

            try {
                const auto &tokenType = Token["token_type"].AsString();
                const auto &idToken = Token["id_token"].AsString();

                CAuthorization Authorization;

                try {
                    Authorization << (tokenType + " " + idToken);

                    if (Authorization.Schema == CAuthorization::asBearer) {
                        Authorization.Token = VerifyToken(Authorization.Token);
                    }

                    const auto &Agent = GetUserAgent(AConnection);
                    const auto &Host = GetHost(AConnection);

                    CStringList SQL;

                    SQL.Add(CString().Format("SELECT * FROM daemon.signin(%s, %s, %s);",
                                             PQQuoteLiteral(Authorization.Token).c_str(),
                                             PQQuoteLiteral(Agent).c_str(),
                                             PQQuoteLiteral(Host).c_str()
                    ));

                    AConnection->Data().Values("authorized", "false");
                    AConnection->Data().Values("signature", "false");
                    AConnection->Data().Values("path", "/sign/in/token");

                    if (!ExecSQL(SQL, AConnection)) {
                        RedirectError(AConnection, errorLocation, 400, "temporarily_unavailable", "Temporarily unavailable.");
                    }

                } catch (jwt::token_expired_exception &e) {
                    RedirectError(AConnection, errorLocation, 403, "invalid_token", e.what());
                } catch (jwt::token_verification_exception &e) {
                    RedirectError(AConnection, errorLocation, 401, "invalid_token", e.what());
                } catch (CAuthorizationError &e) {
                    RedirectError(AConnection, errorLocation, 401, "unauthorized_client", e.what());
                } catch (std::exception &e) {
                    RedirectError(AConnection, errorLocation, 400, "invalid_request", e.what());
                }
            } catch (Delphi::Exception::Exception &e) {
                RedirectError(AConnection, errorLocation, 500, "server_error", e.what());
                Log()->Error(APP_LOG_INFO, 0, "[Token] Message: %s", e.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::SetAuthorizationData(CHTTPServerConnection *AConnection, const CJSON &Payload) {

            auto LReply = AConnection->Reply();

            const auto &session = Payload[_T("session")].AsString();
            if (!session.IsEmpty())
                LReply->SetCookie(_T("SID"), session.c_str(), _T("/"), 60 * SecsPerDay);

            CString Redirect = AConnection->Data()["redirect"];
            if (!Redirect.IsEmpty()) {

                const auto &access_token = Payload[_T("access_token")].AsString();
                const auto &refresh_token = Payload[_T("refresh_token")].AsString();
                const auto &token_type = Payload[_T("token_type")].AsString();
                const auto &expires_in = Payload[_T("expires_in")].AsString();
                const auto &state = Payload[_T("state")].AsString();

                Redirect << "#access_token=" << access_token;

                if (!refresh_token.IsEmpty())
                    Redirect << "&refresh_token=" << CHTTPServer::URLEncode(refresh_token);

                Redirect << "&token_type=" << token_type;
                Redirect << "&expires_in=" << expires_in;
                Redirect << "&session=" << session;

                if (!state.IsEmpty())
                    Redirect << "&state=" << CHTTPServer::URLEncode(state);

                AConnection->Data().Values("redirect", Redirect);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::ParseString(const CString &String, const CStringList &Strings, CStringList &Valid, CStringList &Invalid) {
            Valid.Clear();
            Invalid.Clear();

            if (!String.IsEmpty()) {
                Valid.LineBreak(", ");
                Invalid.LineBreak(", ");

                CStringList Scopes;
                SplitColumns(String, Scopes, ' ');

                for (int i = 0; i < Scopes.Count(); i++) {
                    if (Strings.IndexOfName(Scopes[i]) == -1) {
                        Invalid.Add(Scopes[i]);
                    } else {
                        Valid.Add(Scopes[i]);
                    }
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::DoGet(CHTTPServerConnection *AConnection) {

            auto OnRequestToken = [this](CHTTPClient *Sender, CRequest *Request) {

                const auto &token_uri = Sender->Data()["token_uri"];
                const auto &code = Sender->Data()["code"];
                const auto &client_id = Sender->Data()["client_id"];
                const auto &client_secret = Sender->Data()["client_secret"];
                const auto &redirect_uri = Sender->Data()["redirect_uri"];
                const auto &grant_type = Sender->Data()["grant_type"];

                Request->Content = _T("client_id=");
                Request->Content << CHTTPServer::URLEncode(client_id);

                Request->Content << _T("&client_secret=");
                Request->Content << CHTTPServer::URLEncode(client_secret);

                Request->Content << _T("&grant_type=");
                Request->Content << grant_type;

                Request->Content << _T("&code=");
                Request->Content << CHTTPServer::URLEncode(code);

                Request->Content << _T("&redirect_uri=");
                Request->Content << CHTTPServer::URLEncode(redirect_uri);

                CRequest::Prepare(Request, _T("POST"), token_uri.c_str(), _T("application/x-www-form-urlencoded"));

                DebugRequest(Request);
            };

            auto OnReplyToken = [this, AConnection](CTCPConnection *Sender) {

                auto LConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto LReply = LConnection->Reply();

                DebugReply(LReply);

                const CJSON Json(LReply->Content);

                if (LReply->Status == CReply::ok) {

                    const auto &provider = AConnection->Data()["provider"];

                    if (provider == "default") {

                        SetAuthorizationData(AConnection, Json);
                        // Set after call SetAuthorizationData()
                        const auto &Location = AConnection->Data()["redirect"];
                        Redirect(AConnection, Location, true);

                    } else {

                        SignInToken(AConnection, Json);
                    }
                } else {
                    const auto &Location = AConnection->Data()["redirect_error"];

                    const auto &Error = Json[_T("error")].AsString();
                    const auto &ErrorMessage = Json[_T("error_description")].AsString();

                    RedirectError(AConnection, Location, LReply->Status, Error, ErrorMessage);
                }

                return true;
            };

            auto OnException = [this, AConnection](CTCPConnection *Sender, Delphi::Exception::Exception *AException) {

                auto LConnection = dynamic_cast<CHTTPClientConnection *> (Sender);
                auto LClient = dynamic_cast<CHTTPClient *> (LConnection->Client());

                DebugReply(LConnection->Reply());

                const auto &redirectError = AConnection->Data()["redirect_error"];

                RedirectError(AConnection, redirectError, 500, "server_error", AException->what());

                Log()->Error(APP_LOG_EMERG, 0, "[%s:%d] %s", LClient->Host().c_str(), LClient->Port(),
                             AException->what());
            };

            auto SetSearch = [](const CStringList &Search, CString &Location) {
                for (int i = 0; i < Search.Count(); ++i) {
                    if (i == 0) {
                        Location << "?";
                    } else {
                        Location << "&";
                    }
                    Location << Search.Strings(i);
                }
            };

            auto LRequest = AConnection->Request();
            auto LReply = AConnection->Reply();

            LReply->ContentType = CReply::html;

            CStringList LRouts;
            SplitColumns(LRequest->Location.pathname, LRouts, '/');

            if (LRouts.Count() < 2) {
                AConnection->SendStockReply(CReply::not_found);
                return;
            }

            const auto &SiteConfig = GetSiteConfig(LRequest->Location.Host());

            const auto &redirect_identifier = SiteConfig["oauth2.identifier"];
            const auto &redirect_callback = SiteConfig["oauth2.callback"];
            const auto &redirect_error = SiteConfig["oauth2.error"];

            CString oauthLocation;

            CStringList Search;
            CStringList Valid;
            CStringList Invalid;

            CStringList ResponseType;
            ResponseType.Add("code");
            ResponseType.Add("token");

            CStringList AccessType;
            AccessType.Add("online");
            AccessType.Add("offline");

            CStringList Prompt;
            Prompt.Add("none");
            Prompt.Add("signin");
            Prompt.Add("consent");
            Prompt.Add("select_account");

            const auto &Providers = Server().Providers();

            const auto &Action = LRouts[1].Lower();

            if (Action == "authorize" || Action == "auth") {

                const auto &response_type = LRequest->Params["response_type"];
                const auto &client_id = LRequest->Params["client_id"];
                const auto &access_type = LRequest->Params["access_type"];
                const auto &redirect_uri = LRequest->Params["redirect_uri"];
                const auto &scope = LRequest->Params["scope"];
                const auto &state = LRequest->Params["state"];
                const auto &prompt = LRequest->Params["prompt"];

                if (redirect_uri.IsEmpty()) {
                    RedirectError(AConnection, redirect_error, 400, "invalid_request",
                                  CString().Format("Parameter value redirect_uri cannot be empty."));
                    return;
                }

                const auto &Provider = Providers.Default().Value();
                const auto &Application = Provider.GetClients()[client_id];

                if (Application.IsEmpty()) {
                    RedirectError(AConnection, redirect_error, 401, "invalid_client", CString().Format("The OAuth client was not found."));
                    return;
                }

                if (Provider.RedirectURI(Application).IndexOfName(redirect_uri) == -1) {
                    RedirectError(AConnection, redirect_error, 400, "invalid_request",
                                  CString().Format("Invalid parameter value for redirect_uri: Non-public domains not allowed: %s", redirect_uri.c_str()));
                    return;
                }

                ParseString(response_type, ResponseType, Valid, Invalid);

                if (Invalid.Count() > 0) {
                    RedirectError(AConnection, redirect_error, 400, "unsupported_response_type",
                                  CString().Format("Some requested response type were invalid: {valid=[%s], invalid=[%s]}",
                                                   Valid.Text().c_str(), Invalid.Text().c_str()));
                    return;
                }

                if (response_type == "token")
                    AccessType.Clear();

                if (!access_type.IsEmpty() && AccessType.IndexOfName(access_type) == -1) {
                    RedirectError(AConnection, redirect_error, 400, "invalid_request",
                                  CString().Format("Invalid access_type: %s", access_type.c_str()));
                    return;
                }

                const auto &Scopes = Provider.GetScopes(Application);
                ParseString(scope, Scopes, Valid, Invalid);

                if (Invalid.Count() > 0) {
                    RedirectError(AConnection, redirect_error, 400, "invalid_scope",
                                  CString().Format("Some requested scopes were invalid: {valid=[%s], invalid=[%s]}",
                                                   Valid.Text().c_str(), Invalid.Text().c_str()));
                    return;
                }

                ParseString(prompt, Prompt, Valid, Invalid);

                if (Invalid.Count() > 0) {
                    RedirectError(AConnection, redirect_error, 400, "unsupported_prompt_type",
                                  CString().Format("Some requested prompt type were invalid: {valid=[%s], invalid=[%s]}",
                                                   Valid.Text().c_str(), Invalid.Text().c_str()));
                    return;
                }

                oauthLocation = redirect_identifier;

                Search.Clear();

                Search.AddPair("client_id", client_id);
                Search.AddPair("response_type", response_type);

                if (!redirect_uri.IsEmpty())
                    Search.AddPair("redirect_uri", CHTTPServer::URLEncode(redirect_uri));
                if (!access_type.IsEmpty())
                    Search.AddPair("access_type", access_type);
                if (!scope.IsEmpty())
                    Search.AddPair("scope", CHTTPServer::URLEncode(scope));
                if (!prompt.IsEmpty())
                    Search.AddPair("prompt", CHTTPServer::URLEncode(prompt));
                if (!state.IsEmpty())
                    Search.AddPair("state", CHTTPServer::URLEncode(state));

                SetSearch(Search, oauthLocation);

            } else if (Action == "code") {

                const auto &Error = LRequest->Params["error"];

                if (!Error.IsEmpty()) {
                    const auto ErrorCode = StrToIntDef(LRequest->Params["code"].c_str(), 400);
                    RedirectError(AConnection, redirect_error, ErrorCode, Error, LRequest->Params["error_description"]);
                    return;
                }

                const auto &code = LRequest->Params["code"];
                const auto &state = LRequest->Params["state"];

                if (!code.IsEmpty()) {
                    const auto &providerName = LRouts.Count() == 3 ? LRouts[2].Lower() : "default";
                    const auto &Provider = Providers[providerName].Value();

                    const auto &Application = "web";

                    CString TokenURI(Provider.TokenURI(Application));

                    if (TokenURI.front() == '/') {
                        TokenURI = LRequest->Location.Origin() + TokenURI;
                    }

                    CLocation URI(TokenURI);

                    auto LClient = GetClient(URI.hostname, URI.port);

                    AConnection->Data().Values("provider", providerName);
                    AConnection->Data().Values("redirect", redirect_callback);
                    AConnection->Data().Values("redirect_error", redirect_error);

                    LClient->Data().Values("client_id", Provider.ClientId(Application));
                    LClient->Data().Values("client_secret", Provider.Secret(Application));
                    LClient->Data().Values("grant_type", "authorization_code");
                    LClient->Data().Values("code", code);
                    LClient->Data().Values("redirect_uri", LRequest->Location.Origin() + LRequest->Location.pathname);
                    LClient->Data().Values("token_uri", URI.pathname);

                    LClient->OnRequest(OnRequestToken);
                    LClient->OnExecute(OnReplyToken);
                    LClient->OnException(OnException);

                    LClient->Active(true);
                }

                return;

            } else if (Action == "callback") {

                oauthLocation = redirect_callback;

            } else if (Action == "identifier") {

                const auto& Value = LRequest->Params["value"];

                if (Value.IsEmpty()) {
                    ReplyError(AConnection, 400, "invalid_request", "Invalid request.");
                    return;
                }

                Identifier(AConnection, Value);
                return;
            }

            if (oauthLocation.IsEmpty())
                ReplyError(AConnection, 404, "invalid_request", "Not found.");
            else
                Redirect(AConnection, oauthLocation);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::DoPost(CHTTPServerConnection *AConnection) {

            auto LRequest = AConnection->Request();
            auto LReply = AConnection->Reply();

            LReply->ContentType = CReply::json;

            CStringList LRouts;
            SplitColumns(LRequest->Location.pathname, LRouts, '/');

            if (LRouts.Count() < 2) {
                ReplyError(AConnection, 404, "invalid_request", "Not found.");
                return;
            }

            AConnection->Data().Values("oauth2", "true");
            AConnection->Data().Values("path", LRequest->Location.pathname);

            try {
                const auto &Action = LRouts[1].Lower();

                if (Action == "token") {
                    DoToken(AConnection);
                } else {
                    ReplyError(AConnection, 404, "invalid_request", "Not found.");
                }
            } catch (std::exception &e) {
                ReplyError(AConnection, 400, "invalid_request", e.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CAuthServer::Heartbeat() {
            auto now = Now();

            if ((now >= m_FixedDate)) {
                m_FixedDate = now + (CDateTime) 30 * 60 / SecsPerDay; // 30 min
                LoadCerts();
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CAuthServer::Enabled() {
            if (m_ModuleStatus == msUnknown)
                m_ModuleStatus = Config()->IniFile().ReadBool("worker/AuthServer", "enable", true) ? msEnabled : msDisabled;
            return m_ModuleStatus == msEnabled;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CAuthServer::CheckConnection(CHTTPServerConnection *AConnection) {
            const auto& Location = AConnection->Request()->Location;
            return Location.pathname.SubString(0, 8) == _T("/oauth2/");
        }
        //--------------------------------------------------------------------------------------------------------------
    }
}
}