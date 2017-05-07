-- |
-- Module      : Network.TLS.ErrT
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- a simple compat ErrorT and other error stuff
{-# LANGUAGE CPP #-}
module Network.TLS.ErrT
    ( ErrT
    , Error(..)
    , MonadError(..)
    , hoistEither
    , hoistMaybe
    , left
    , newErrT
    , runErrT

    , catchExceptionT
    ) where

import Control.Concurrent.Async (waitCatch, withAsync)
import Control.Exception (SomeException)

#if MIN_VERSION_mtl(2,2,1)
import Control.Monad.Except
import Control.Monad.Error.Class (Error(..))
{-# INLINE runErrT #-}
runErrT :: ExceptT e m a -> m (Either e a)
runErrT = runExceptT
type ErrT = ExceptT
#else
import Control.Monad.Error
{-# INLINE runErrT #-}
runErrT :: ErrorT e m a -> m (Either e a)
runErrT = runErrorT
type ErrT = ErrorT
#endif

{-# INLINE hoistEither #-}
hoistEither :: Monad m => Either e a -> ErrT e m a
hoistEither = ExceptT . return

{-# INLINE hoistMaybe #-}
hoistMaybe :: Monad m => e -> Maybe a -> ErrT e m a
hoistMaybe err = ExceptT . return . maybe (Left err) Right

{-# INLINE left #-}
left :: Monad m => e -> ErrT e m a
left = ExceptT . return . Left

{-# INLINE newErrT #-}
newErrT :: Monad m => m (Either e a) -> ErrT e m a
newErrT = ExceptT


catchExceptionT :: IO a -> (SomeException -> ErrT e IO a) -> ErrT e IO a
catchExceptionT action handler =
    liftIO (withAsync action waitCatch) >>= either handler return
