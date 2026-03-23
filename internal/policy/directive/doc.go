// Package directive provides the @Policy annotation pattern for SecurePrompt.
//
// Since Go lacks native decorators, this package uses functional wrappers and
// struct tags to achieve declarative policy governance with minimal code changes.
//
// # Quick Start
//
//	// 1. Define your prompt function
//	func myPrompt(ctx context.Context, input Input) (string, error) { ... }
//
//	// 2. Wrap once during initialization
//	var myPrompt = directive.Apply(
//		myPrompt,
//		directive.PolicyConfig{Profile: "strict", BlockOnViolation: true},
//	)
//
//	// 3. Use the wrapped function - policy enforced automatically
//	prompt, err := myPrompt(ctx, data)
//
// # Optional: Code Generation
//
//go:generate go run generate.go -dir=. -out=directive_generated.go -pkg=directive
package directive
