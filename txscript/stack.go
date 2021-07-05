package txscript

type stack []command

func (s *stack) PushOpcode(c opcode) *stack {
	*s = append(*s, c)
	return s
}

func (s *stack) PushElement(el element) *stack {
	*s = append(*s, el)
	return s
}

func (s *stack) Pop() (*stack, command) {
	l := len(*s)
	if l == 0 {
		panic("stack is already empty")
	}

	el := (*s)[l-1]
	*s = (*s)[:l-1]
	return s, el
}
