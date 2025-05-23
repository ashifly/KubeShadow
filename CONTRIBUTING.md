# Contributing to KubeShadow

Thank you for your interest in contributing to KubeShadow! This document provides guidelines and instructions for contributing.

## Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/KubeShadow.git
   cd KubeShadow
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/original-owner/KubeShadow.git
   ```

## Development Workflow

1. Create a new branch for your feature/fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following our coding standards:
   - Use Go standard formatting (`go fmt`)
   - Follow Go best practices
   - Write tests for new functionality
   - Update documentation as needed

3. Run tests:
   ```bash
   go test ./...
   ```

4. Commit your changes:
   ```bash
   git commit -m "feat: add new feature"
   ```

5. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

6. Create a Pull Request

## Code Standards

- Follow [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Write clear, descriptive commit messages
- Include tests for new functionality
- Update documentation for new features
- Keep code modular and maintainable

## Testing

- Write unit tests for new functionality
- Ensure all tests pass before submitting PR
- Include integration tests for complex features
- Maintain or improve code coverage

## Documentation

- Update README.md for significant changes
- Add inline documentation for complex code
- Update API documentation if needed
- Include examples for new features

## Pull Request Process

1. Update documentation
2. Add tests for new functionality
3. Ensure all tests pass
4. Update CHANGELOG.md
5. Submit PR with clear description

## Questions?

Feel free to open an issue for any questions about contributing. 