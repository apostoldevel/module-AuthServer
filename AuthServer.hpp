/*++

Program name:

  Apostol Web Service

Module Name:

  AuthServer.hpp

Notices:

  Module: OAuth 2 Authorization Server

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

#ifndef APOSTOL_AUTHSERVER_HPP
#define APOSTOL_AUTHSERVER_HPP
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Workers {

        //--------------------------------------------------------------------------------------------------------------

        //-- CAuthServer -----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CAuthServer: public CApostolModule {
        private:

            CDateTime m_FixedDate;

            void InitMethods() override;

            void LoadCerts();

            static void QueryException(CPQPollQuery *APollQuery, const std::exception &e);

            CString CreateToken(const CCleanToken& CleanToken);
            CString VerifyToken(const CString &Token);

            static void ParseString(const CString &String, const CStringList &Strings, CStringList &Valid, CStringList &Invalid);

            static int CheckOAuth2Error(const CJSON &Json, CString &Error, CString &ErrorDescription);
            static int CheckError(const CJSON &Json, CString &ErrorMessage, bool RaiseIfError = false);

            static CReply::CStatusType ErrorCodeToStatus(int ErrorCode);

            static void RedirectError(CHTTPServerConnection *AConnection, const CString &Location, int ErrorCode, const CString &Error, const CString &Message);
            static void ReplyError(CHTTPServerConnection *AConnection, int ErrorCode, const CString &Error, const CString &Message);

            static void SetAuthorizationData(CHTTPServerConnection *AConnection, const CJSON &Payload);
            void SignInToken(CHTTPServerConnection *AConnection, const CJSON &Token);

        protected:

            void DoGet(CHTTPServerConnection *AConnection) override;
            void DoPost(CHTTPServerConnection *AConnection);

            void DoToken(CHTTPServerConnection *AConnection);

            void DoPostgresQueryExecuted(CPQPollQuery *APollQuery) override;
            void DoPostgresQueryException(CPQPollQuery *APollQuery, Delphi::Exception::Exception *AException) override;

        public:

            explicit CAuthServer(CModuleProcess *AProcess);

            ~CAuthServer() override = default;

            static class CAuthServer *CreateModule(CModuleProcess *AProcess) {
                return new CAuthServer(AProcess);
            }

            void Identifier(CHTTPServerConnection *AConnection, const CString &Identifier);

            void Authorize(CHTTPServerConnection *AConnection, const CString &Session, const CString &Path, const CString &Resource);

            void Heartbeat() override;

            bool Enabled() override;
            bool CheckConnection(CHTTPServerConnection *AConnection) override;

        };
    }
}

using namespace Apostol::Workers;
}
#endif //APOSTOL_AUTHSERVER_HPP
