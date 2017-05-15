{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Monadic

import PipeChan
import Connection
import Marshalling
import Ciphers

import Data.Maybe (fromJust, isJust)
import Data.List (intersect)

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as L
import Network.TLS
import Network.TLS.Extra
import Control.Applicative
import Control.Concurrent
import Control.Monad

import Data.IORef

import System.Timeout

prop_pipe_work :: PropertyM IO ()
prop_pipe_work = do
    pipe <- run newPipe
    _ <- run (runPipe pipe)

    let bSize = 16
    n <- pick (choose (1, 32))

    let d1 = B.replicate (bSize * n) 40
    let d2 = B.replicate (bSize * n) 45

    d1' <- run (writePipeA pipe d1 >> readPipeB pipe (B.length d1))
    d1 `assertEq` d1'

    d2' <- run (writePipeB pipe d2 >> readPipeA pipe (B.length d2))
    d2 `assertEq` d2'

    return ()

recvDataNonNull :: Context -> IO C8.ByteString
recvDataNonNull ctx =
    recvData ctx >>= either
            (\e -> error $ "recvDataNonNull: " ++ show e)
            (\l -> if B.null l then recvDataNonNull ctx else return l)

runTLSPipe :: (ClientParams, ServerParams) -> (Context -> Chan C8.ByteString -> IO ()) -> (Chan C8.ByteString -> Context -> IO ()) -> PropertyM IO ()
runTLSPipe params tlsServer tlsClient = do
    (startQueue, resultQueue) <- run (establishDataPipe params tlsServer tlsClient)
    -- send some data
    d <- B.pack <$> pick (someWords8 256)
    run $ writeChan startQueue d
    -- receive it
    dres <- run $ timeout 10000000 $ readChan resultQueue
    -- check if it equal
    Just d `assertEq` dres
    return ()

runTLSPipeSimple :: (ClientParams, ServerParams) -> PropertyM IO ()
runTLSPipeSimple params = runTLSPipe params tlsServer tlsClient
  where tlsServer ctx queue = do
            errorLeft <$> handshake ctx
            d <- recvDataNonNull ctx
            writeChan queue d
            return ()
        tlsClient queue ctx = do
            errorLeft <$> handshake ctx
            d <- readChan queue
            errorLeft <$> sendData ctx (L.fromChunks [d])
            bye ctx
            return ()

runTLSInitFailure :: (ClientParams, ServerParams) -> PropertyM IO ()
runTLSInitFailure params = do
    (cRes, sRes) <- run (initiateDataPipe params tlsServer tlsClient)
    assertIsLeft cRes
    assertIsLeft sRes
  where tlsServer ctx = do
            r <- handshake ctx
            bye ctx
            case r of
                Left e -> pure $ Left e
                Right () -> pure $ Right ("server success" :: String)
        tlsClient ctx = do
            r <- handshake ctx
            bye ctx
            case r of
                Left e -> pure $ Left e
                Right () -> pure $ Right ("client success" :: String)

prop_handshake_initiate :: PropertyM IO ()
prop_handshake_initiate = do
    params  <- pick arbitraryPairParams
    runTLSPipeSimple params

prop_handshake_ciphersuites :: PropertyM IO ()
prop_handshake_ciphersuites = do
    let clientVersions = [TLS12]
        serverVersions = [TLS12]
    clientCiphers <- pick arbitraryCiphers
    serverCiphers <- pick arbitraryCiphers
    (clientParam,serverParam) <- pick $ arbitraryPairParamsWithVersionsAndCiphers
                                            (clientVersions, serverVersions)
                                            (clientCiphers, serverCiphers)
    let shouldFail = null (clientCiphers `intersect` serverCiphers)
    if shouldFail
        then runTLSInitFailure (clientParam,serverParam)
        else runTLSPipeSimple  (clientParam,serverParam)

prop_handshake_hashsignatures :: PropertyM IO ()
prop_handshake_hashsignatures = do
    let clientVersions = [TLS12]
        serverVersions = [TLS12]
        ciphers = [ cipher_ECDHE_RSA_AES256GCM_SHA384
                  , cipher_ECDHE_RSA_AES128CBC_SHA
                  , cipher_DHE_RSA_AES128_SHA1
                  , cipher_DHE_DSS_AES128_SHA1
                  ]
    (clientParam,serverParam) <- pick $ arbitraryPairParamsWithVersionsAndCiphers
                                            (clientVersions, serverVersions)
                                            (ciphers, ciphers)
    clientHashSigs <- pick arbitraryHashSignatures
    serverHashSigs <- pick arbitraryHashSignatures
    let clientParam' = clientParam { clientSupported = (clientSupported clientParam)
                                       { supportedHashSignatures = clientHashSigs }
                                   }
        serverParam' = serverParam { serverSupported = (serverSupported serverParam)
                                       { supportedHashSignatures = serverHashSigs }
                                   }
        shouldFail = null (clientHashSigs `intersect` serverHashSigs)
    if shouldFail
        then runTLSInitFailure (clientParam',serverParam')
        else runTLSPipeSimple  (clientParam',serverParam')

prop_handshake_groups :: PropertyM IO ()
prop_handshake_groups = do
    let clientVersions = [TLS12]
        serverVersions = [TLS12]
        ciphers = [ cipher_ECDHE_RSA_AES256GCM_SHA384
                  , cipher_ECDHE_RSA_AES128CBC_SHA
                  ]
    (clientParam,serverParam) <- pick $ arbitraryPairParamsWithVersionsAndCiphers
                                            (clientVersions, serverVersions)
                                            (ciphers, ciphers)
    clientGroups <- pick arbitraryGroups
    serverGroups <- pick arbitraryGroups
    let clientParam' = clientParam { clientSupported = (clientSupported clientParam)
                                       { supportedGroups = clientGroups }
                                   }
        serverParam' = serverParam { serverSupported = (serverSupported serverParam)
                                       { supportedGroups = serverGroups }
                                   }
        shouldFail = null (clientGroups `intersect` serverGroups)
    if shouldFail
        then runTLSInitFailure (clientParam',serverParam')
        else runTLSPipeSimple  (clientParam',serverParam')

prop_handshake_client_auth :: PropertyM IO ()
prop_handshake_client_auth = do
    (clientParam,serverParam) <- pick arbitraryPairParams
    cred <- pick arbitraryClientCredential
    let clientParam' = clientParam { clientHooks = (clientHooks clientParam)
                                       { onCertificateRequest = \_ -> return $ Just cred }
                                   }
        serverParam' = serverParam { serverWantClientCert = True
                                   , serverHooks = (serverHooks serverParam)
                                        { onClientCertificate = validateChain cred }
                                   }
    runTLSPipeSimple (clientParam',serverParam')
  where validateChain cred chain
            | chain == fst cred = return CertificateUsageAccept
            | otherwise         = return (CertificateUsageReject CertificateRejectUnknownCA)

prop_handshake_alpn :: PropertyM IO ()
prop_handshake_alpn = do
    (clientParam,serverParam) <- pick arbitraryPairParams
    let clientParam' = clientParam { clientHooks = (clientHooks clientParam)
                                       { onSuggestALPN = return $ Just ["h2", "http/1.1"] }
                                    }
        serverParam' = serverParam { serverHooks = (serverHooks serverParam)
                                        { onALPNClientSuggest = Just alpn }
                                   }
        params' = (clientParam',serverParam')
    runTLSPipe params' tlsServer tlsClient
  where tlsServer ctx queue = do
            errorLeft <$> handshake ctx
            proto <- getNegotiatedProtocol ctx
            Just "h2" `assertEq` proto
            d <- recvDataNonNull ctx
            writeChan queue d
            return ()
        tlsClient queue ctx = do
            errorLeft <$> handshake ctx
            proto <- getNegotiatedProtocol ctx
            Just "h2" `assertEq` proto
            d <- readChan queue
            errorLeft <$> sendData ctx (L.fromChunks [d])
            bye ctx
            return ()
        alpn xs
          | "h2"    `elem` xs = return "h2"
          | otherwise         = return "http/1.1"

prop_handshake_sni :: PropertyM IO ()
prop_handshake_sni = do
    (clientParam,serverParam) <- pick arbitraryPairParams
    let clientParam' = clientParam { clientServerIdentification = (serverName, "")
                                   , clientUseServerNameIndication = True
                                    }
        params' = (clientParam',serverParam)
    runTLSPipe params' tlsServer tlsClient
  where tlsServer ctx queue = do
            errorLeft <$> handshake ctx
            sni <- getClientSNI ctx
            Just serverName `assertEq` sni
            d <- recvDataNonNull ctx
            writeChan queue d
            return ()
        tlsClient queue ctx = do
            errorLeft <$> handshake ctx
            d <- readChan queue
            errorLeft <$> sendData ctx (L.fromChunks [d])
            bye ctx
            return ()
        serverName = "haskell.org"

prop_handshake_renegotiation :: PropertyM IO ()
prop_handshake_renegotiation = do
    (cparams, sparams) <- pick arbitraryPairParams
    let sparams' = sparams {
            serverSupported = (serverSupported sparams) {
                 supportedClientInitiatedRenegotiation = True
               }
          }
    runTLSPipe (cparams, sparams') tlsServer tlsClient
  where tlsServer ctx queue = do
            errorLeft <$> handshake ctx
            d <- recvDataNonNull ctx
            writeChan queue d
            return ()
        tlsClient queue ctx = do
            errorLeft <$> handshake ctx
            errorLeft <$> handshake ctx
            d <- readChan queue
            errorLeft <$> sendData ctx (L.fromChunks [d])
            bye ctx
            return ()

prop_handshake_session_resumption :: PropertyM IO ()
prop_handshake_session_resumption = do
    sessionRef <- run $ newIORef Nothing
    let sessionManager = oneSessionManager sessionRef

    plainParams <- pick arbitraryPairParams
    let params = setPairParamsSessionManager sessionManager plainParams

    runTLSPipeSimple params

    -- and resume
    sessionParams <- run $ readIORef sessionRef
    assert (isJust sessionParams)
    let params2 = setPairParamsSessionResuming (fromJust sessionParams) params

    runTLSPipeSimple params2

assertEq :: (Show a, Monad m, Eq a) => a -> a -> m ()
assertEq expected got = unless (expected == got) $ error ("got " ++ show got ++ " but was expecting " ++ show expected)

assertIsLeft :: (Show b, Monad m) => Either a b -> m ()
assertIsLeft (Left  _) = return()
assertIsLeft (Right b) = error ("got " ++ show b ++ " but was expecting a failure")

errorLeft :: Either TLSError a -> a
errorLeft = either (error . show) id

main :: IO ()
main = defaultMain $ testGroup "tls"
    [ tests_marshalling
    , tests_ciphers
    , tests_handshake
    ]
  where -- lowlevel tests to check the packet marshalling.
        tests_marshalling = testGroup "Marshalling"
            [ testProperty "Header" prop_header_marshalling_id
            , testProperty "Handshake" prop_handshake_marshalling_id
            ]
        tests_ciphers = testGroup "Ciphers"
            [ testProperty "Bulk" propertyBulkFunctional ]

        -- high level tests between a client and server with fake ciphers.
        tests_handshake = testGroup "Handshakes"
            [ testProperty "Setup" (monadicIO prop_pipe_work)
            , testProperty "Initiation" (monadicIO prop_handshake_initiate)
            , testProperty "Hash and signatures" (monadicIO prop_handshake_hashsignatures)
            , testProperty "Cipher suites" (monadicIO prop_handshake_ciphersuites)
            , testProperty "Groups" (monadicIO prop_handshake_groups)
            , testProperty "Client authentication" (monadicIO prop_handshake_client_auth)
            , testProperty "ALPN" (monadicIO prop_handshake_alpn)
            , testProperty "SNI" (monadicIO prop_handshake_sni)
            , testProperty "Renegotiation" (monadicIO prop_handshake_renegotiation)
            , testProperty "Resumption" (monadicIO prop_handshake_session_resumption)
            ]
