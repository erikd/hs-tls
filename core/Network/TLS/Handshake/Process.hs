-- |
-- Module      : Network.TLS.Handshake.Process
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- process handshake message received
--
module Network.TLS.Handshake.Process
    ( processHandshake
    , startHandshake
    , getHandshakeDigest
    ) where

import Control.Concurrent.MVar
import Control.Monad.State.Strict (gets)
import Control.Monad
import Control.Monad.IO.Class (liftIO)

import Network.TLS.Types (Role(..), invertRole)
import Network.TLS.Util
import Network.TLS.Packet
import Network.TLS.ErrT
import Network.TLS.Struct
import Network.TLS.State
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Handshake.State
import Network.TLS.Handshake.Key
import Network.TLS.Extension
import Network.TLS.Parameters
import Data.X509 (CertificateChain(..), Certificate(..), getCertificate)

processHandshake :: Context -> Handshake -> ErrT TLSError IO ()
processHandshake ctx hs = do
    role <- usingStateT ctx isClientContext
    case hs of
        ClientHello cver ran _ cids _ ex _ -> when (role == ServerRole) $ do
            mapM_ (usingStateT ctx . processClientExtension) ex
            -- RFC 5746: secure renegotiation
            -- TLS_EMPTY_RENEGOTIATION_INFO_SCSV: {0x00, 0xFF}
            when (secureRenegotiation && (0xff `elem` cids)) $
                usingStateT ctx $ setSecureRenegotiation True
            liftIO $ startHandshake ctx cver ran
        Certificates certs            -> processCertificates role certs
        ClientKeyXchg content         -> when (role == ServerRole) $ do
            processClientKeyXchg ctx content
        Finished fdata                -> processClientFinished ctx fdata
        _                             -> return ()
    let encoded = encodeHandshake hs
    when (certVerifyHandshakeMaterial hs) $ usingHStateT ctx $ addHandshakeMessage encoded
    when (finishHandshakeTypeMaterial $ typeOfHandshake hs) $ usingHStateT ctx $ updateHandshakeDigest encoded
  where secureRenegotiation = supportedSecureRenegotiation $ ctxSupported ctx
        -- RFC5746: secure renegotiation
        -- the renegotiation_info extension: 0xff01
        processClientExtension (ExtensionRaw 0xff01 content) | secureRenegotiation = do
            v <- getVerifiedData ClientRole
            let bs = extensionEncode (SecureRenegotiation v Nothing)
            unless (bs `bytesEq` content) $ throwError $ Error_Protocol ("client verified data not matching: " ++ show v ++ ":" ++ show content, True, HandshakeFailure)

            setSecureRenegotiation True
        -- unknown extensions
        processClientExtension _ = return ()

        processCertificates :: Role -> CertificateChain -> ErrT TLSError IO ()
        processCertificates ServerRole (CertificateChain []) = return ()
        processCertificates ClientRole (CertificateChain []) =
            left $ Error_Protocol ("server certificate missing", True, HandshakeFailure)
        processCertificates _ (CertificateChain (c:_)) =
            usingHStateT ctx $ setPublicKey pubkey
          where pubkey = certPubKey $ getCertificate c

-- process the client key exchange message. the protocol expects the initial
-- client version received in ClientHello, not the negotiated version.
-- in case the version mismatch, generate a random master secret
processClientKeyXchg :: Context -> ClientKeyXchgAlgorithmData -> ErrT TLSError IO ()
processClientKeyXchg ctx (CKX_RSA encryptedPremaster) = do
    (rver, role, random) <- usingStateT ctx $ do
        (,,) <$> getVersion <*> isClientContext <*> genRandom 48
    ePremaster <- decryptRSA ctx encryptedPremaster
    usingHStateT ctx $ do
        expectedVer <- gets hstClientVersion
        case ePremaster of
            Left _          -> setMasterSecretFromPre rver role random
            Right premaster -> case decodePreMasterSecret premaster of
                Left _                   -> setMasterSecretFromPre rver role random
                Right (ver, _)
                    | ver /= expectedVer -> setMasterSecretFromPre rver role random
                    | otherwise          -> setMasterSecretFromPre rver role premaster
processClientKeyXchg ctx (CKX_DH clientDHValue) = do
    rver <- usingStateT ctx getVersion
    role <- usingStateT ctx isClientContext

    serverParams <- usingHStateT ctx getServerDHParams
    dhpriv       <- usingHStateT ctx getDHPrivate
    let premaster = dhGetShared (serverDHParamsToParams serverParams) dhpriv clientDHValue
    usingHStateT ctx $ setMasterSecretFromPre rver role premaster

processClientKeyXchg ctx (CKX_ECDH bytes) = do
    ServerECDHParams grp _ <- usingHStateT ctx getServerECDHParams
    case decodeGroupPublic grp bytes of
      Left _ -> left $ Error_Protocol ("client public key cannot be decoded", True, HandshakeFailure)
      Right clipub -> do
          srvpri <- usingHStateT ctx getECDHPrivate
          case groupGetShared clipub srvpri of
              Just premaster -> do
                  rver <- usingStateT ctx getVersion
                  role <- usingStateT ctx isClientContext
                  usingHStateT ctx $ setMasterSecretFromPre rver role premaster
              Nothing -> left $ Error_Protocol ("cannote generate a shared secret on ECDH", True, HandshakeFailure)

processClientFinished :: Context -> FinishedData -> ErrT TLSError IO ()
processClientFinished ctx fdata = do
    (cc,ver) <- usingStateT ctx $ (,) <$> isClientContext <*> getVersion
    expected <- usingHStateT ctx $ getHandshakeDigest ver $ invertRole cc
    when (expected /= fdata) $ do
        left $ Error_Protocol("bad record mac", True, BadRecordMac)
    usingStateT ctx $ updateVerifiedData ServerRole fdata
    return ()

-- initialize a new Handshake context (initial handshake or renegotiations)
startHandshake :: Context -> Version -> ClientRandom -> IO ()
startHandshake ctx ver crand =
    let hs = Just $ newEmptyHandshake ver crand
    in liftIO $ void $ swapMVar (ctxHandshake ctx) hs
