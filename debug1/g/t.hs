
import System.Posix.Process (getProcessID)

main = do
    print =<< getProcessID
    interact id
