# Contributing Guidelines

## Team Structure

This project is designed for two cybersecurity students:
- **Red Team Student**: Works in `red_team/` directory
- **Blue Team Student**: Works in `blue_team/` directory

## Workflow

1. **Fork the repository** (if working on separate forks)
2. **Create a branch** for your feature:
   ```bash
   git checkout -b red-team/feature-name
   # or
   git checkout -b blue-team/feature-name
   ```
3. **Make your changes** in the appropriate directory
4. **Test your code** thoroughly
5. **Commit with clear messages**:
   ```bash
   git commit -m "Red Team: Add new port scanning feature"
   ```
6. **Push and create a Pull Request**

## Code Standards

- Follow PEP 8 for Python code
- Add docstrings to all functions and classes
- Include error handling
- Add comments for complex logic
- Test your code before committing

## Documentation

- Update README files when adding new tools
- Document all command-line arguments
- Include usage examples
- Add security warnings where appropriate

## Security Considerations

- Never commit sensitive information (passwords, keys, tokens)
- Always include legal/ethical disclaimers
- Test only in controlled environments
- Follow responsible disclosure practices

## Collaboration

- Communicate with your partner about changes
- Review each other's code
- Share findings and reports
- Coordinate on shared utilities

## Questions?

If you have questions, create an issue or discuss with your partner.

