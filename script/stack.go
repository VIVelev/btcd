package script

type stack []command

func (s *stack) Push(c command) *stack {
	*s = append(*s, c)
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

func (s *stack) Peek() command {
	l := len(*s)
	if l == 0 {
		panic("stack is already empty")
	}
	return (*s)[l-1]
}
