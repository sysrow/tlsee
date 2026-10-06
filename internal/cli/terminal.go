package cli

import (
	"io"
	"os"
)

// isTerminal asks the operating system whether w is a terminal. Character
// devices such as the null device are not necessarily terminals.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok || f == nil {
		return false
	}
	conn, err := f.SyscallConn()
	if err != nil {
		return false
	}
	var terminal bool
	// Control keeps the descriptor open during the query, including when
	// another goroutine closes the file concurrently.
	err = conn.Control(func(fd uintptr) { terminal = isTerminalFD(fd) })
	return err == nil && terminal
}
