{-# language BangPatterns #-}

module FortiEdr.Syslog
  ( Attribute(..)
  , decode
  ) where

import Net.Types (IP)
import Data.Bytes (Bytes)
import Data.Word (Word64)
import Data.Primitive (SmallArray)

-- | Decode the message in a FortiEDR syslog. Do not pass this function the
-- full syslog:
--
-- > <133>1 2021-05-25T15:47:37.000Z layer3com.console.ensilo.com FortiEDR - - - Message Type: Security Event;Organization: WidgetCorp;...
--
-- Rather, use @Syslog.Ietf.decode@ to get the message from FortiEDR\'s
-- RFC 5424 syslog:
--
-- > Message Type: Security Event;Organization: WidgetCorp;...
--
-- Then, this function on that message.
decode :: Bytes -> Maybe (SmallArray Attribute)
decode !_ = Nothing

-- ^ Data constructor annatotions describe the field name as it appears in
-- the logs.
data Attribute
  = MessageType !Bytes -- ^ Message Type
  | Organization !Bytes -- ^ Organization
  | OrganizationId !Word64 -- ^ Organization ID
  | EventId !Word64 -- ^ Event ID
  | RawDataId !Word64 -- ^ Raw Data ID
  | DeviceName !Bytes -- ^ Device Name
  | DeviceState !Bytes -- ^ Device State
  | OperatingSystem !Bytes -- ^ Operating System
  | ProcessName !Bytes -- ^ Process Name
  | ProcessPath !Bytes -- ^ Process Path
  | ProcessType !Bytes -- ^ Process Type
  | Severity !Bytes -- ^ Severity
  | Classification !Bytes -- ^ Classification
  | Destination !Bytes -- ^ Destination
  | Action !Bytes -- ^ Action
  | SourceIp {-# UNPACK #-} !IP -- ^ Source IP
