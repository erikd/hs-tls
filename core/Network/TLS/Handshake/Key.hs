-- |
-- Module      : Network.TLS.Handshake.Key
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- functions for RSA operations
--
module Network.TLS.Handshake.Key
    ( encryptRSA
    , signPrivate
    , decryptRSA
    , verifyPublic
    , generateDHE
    , generateECDHE
    , generateECDHEShared
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Network.TLS.Handshake.State
import Network.TLS.State (withRNG, getVersion)
import Network.TLS.Crypto
import Network.TLS.Types
import Network.TLS.Context.Internal
import Network.TLS.ErrT
import Network.TLS.Struct

{- if the RSA encryption fails we just return an empty bytestring, and let the protocol
 - fail by itself; however it would be probably better to just report it since it's an internal problem.
 -}
encryptRSA :: Context -> ByteString -> ErrT TLSError IO ByteString
encryptRSA ctx content = do
    publicKey <- usingHStateT ctx getRemotePublicKey
    usingStateT ctx $ do
        v <- withRNG $ kxEncrypt publicKey content
        case v of
            Left err       -> fail ("rsa encrypt failed: " ++ show err)
            Right econtent -> return econtent

signPrivate :: Context -> Role -> SignatureParams -> ByteString -> ErrT TLSError IO ByteString
signPrivate ctx _ params content = do
    privateKey <- usingHStateT ctx getLocalPrivateKey
    usingStateT ctx $ do
        r <- withRNG $ kxSign privateKey params content
        case r of
            Left err       -> fail ("sign failed: " ++ show err)
            Right econtent -> return econtent

decryptRSA :: Context -> ByteString -> ErrT TLSError IO (Either KxError ByteString)
decryptRSA ctx econtent = do
    privateKey <- usingHStateT ctx getLocalPrivateKey
    usingStateT ctx $ do
        ver <- getVersion
        let cipher = if ver < TLS10 then econtent else B.drop 2 econtent
        withRNG $ kxDecrypt privateKey cipher

verifyPublic :: Context -> Role -> SignatureParams -> ByteString -> ByteString -> ErrT TLSError IO Bool
verifyPublic ctx _ params econtent sign = do
    publicKey <- usingHStateT ctx getRemotePublicKey
    return $ kxVerify publicKey params econtent sign

generateDHE :: Context -> DHParams -> ErrT TLSError IO (DHPrivate, DHPublic)
generateDHE ctx dhp = usingStateT ctx $ withRNG $ dhGenerateKeyPair dhp

generateECDHE :: Context -> Group -> ErrT TLSError IO (GroupPrivate, GroupPublic)
generateECDHE ctx grp = usingStateT ctx $ withRNG $ groupGenerateKeyPair grp

generateECDHEShared :: Context -> GroupPublic -> ErrT TLSError IO (GroupPublic, GroupKey)
generateECDHEShared ctx pub = usingStateT ctx $ withRNG $ groupGetPubShared pub
