{-# language LambdaCase #-}

import Control.Monad (when)
import Data.Bytes (Bytes)
import Data.Foldable (for_)
import Data.List (find)

import qualified Chronos
import qualified Data.Bytes as Bytes
import qualified Data.Primitive as PM
import qualified FortiEdr.Syslog as F
import qualified Net.IP as IP

main :: IO ()
main = do
  putStrLn "Start"
  putStrLn "Test A"
  testA
  putStrLn "Finish"

testA :: IO ()
testA = do
  let attrs = F.decode exA
  for_ attrs
    (\case
      F.MessageType n -> when (n /= Bytes.fromAsciiString "Security Event") (fail "wrong message type")
      F.OrganizationId n -> when (n /= 5714) (fail "wrong organization id")
      F.SourceIp n -> when (n /= IP.ipv4 192 0 2 19) (fail "wrong source ip")
      F.FirstSeen x -> when
        (x /= Chronos.datetimeFromYmdhms 2021 5 24 5 27 44)
        (fail "wrong first seen")
      F.MacAddress macs -> when (PM.sizeofPrimArray macs /= 2) (fail "wrong number of MAC addresses")
      _ -> pure ()
    )
  case find (\case {F.FirstSeen{} -> True; _ -> False}) attrs of
    Nothing -> fail "missing first seen"
    _ -> pure ()
  case find (\case {F.LastSeen{} -> True; _ -> False}) attrs of
    Nothing -> fail "missing last seen"
    _ -> pure ()
  case find (\case {F.MacAddress{} -> True; _ -> False}) attrs of
    Nothing -> fail "missing mac address"
    _ -> pure ()

-- Anonymized example log
exA :: Bytes
exA = Bytes.fromAsciiString
  "<133>1 2021-05-25T15:47:37.000Z foo.example.com FortiEDR - - - Message Type:\
  \ Security Event;Organization: WidgetCorp;Organization ID: 5714;Event ID: 3478026;Raw Data\
  \ ID: 1447934104;Device Name: FooBar90420L;Device State: Running;Operating System: Windows\
  \ 10 Pro;Process Name: taskhostw.exe;Process\
  \ Path: \\Device\\HarddiskVolume3\\Windows\\System32\\taskhostw.exe;Process Type:\
  \ 64bit;Severity: Critical;Classification: Suspicious;Destination: File Delete Attempt;First\
  \ Seen: 24-May-2021, 05:27:44;Last Seen: 25-May-2021, 08:47:37;Action: Blocked;Count:\
  \ 1720;Certificate: yes;Rules List: File Encryptor - Suspicious file modification;Users:\
  \ Widget\\John.Doe;MAC Address: 3C-0D-98-09-46-E9,E8-D8-D2-F7-3F-A7;Script: N/A;Script\
  \ Path: N/A;Autonomous System: N/A;Country: N/A;Process Hash:\
  \ FED3B4A753A6541389AAB70C69E6242E07549CCD;Source IP: 192.0.2.19"
