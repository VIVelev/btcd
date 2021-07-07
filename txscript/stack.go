package txscript

import "fmt"

// command can be either a opcode or an element
type command interface {
	fmt.Stringer
	Equal(other command) bool
}

type stack []command

func (s *stack) Copy() *stack {
	newStack := new(stack)
	for _, c := range s.Iter() {
		switch c := c.(type) {
		case opcode:
			newStack.PushOpcode(c)
		case element:
			newStack.PushElement(c)
		}
	}

	return newStack
}

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

func (s *stack) PopFront() (*stack, command) {
	l := len(*s)
	if l == 0 {
		panic("stack is already empty")
	}
	el := (*s)[0]
	*s = (*s)[1:]
	return s, el
}

func (s *stack) Iter() stack {
	return *s
}

func (s *stack) Peek() command {
	l := len(*s)
	if l == 0 {
		panic("stack is already empty")
	}
	return (*s)[l-1]
}

func (s *stack) PeekAt(i int) command {
	l := len(*s)
	if l == 0 {
		panic("stack is already empty")
	}
	return (*s)[i]
}
