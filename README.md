# PatientRecords - Secure Medical Records Management

A blockchain-based system for managing patient medical records with controlled nurse access on Stacks.

## Features

- Patient registration with encrypted data hashes
- Granular nurse access control with expiration
- Medical entry logging with timestamps
- Access revocation capabilities
- Critical entry marking

## Contract Functions

### Public Functions
- `register-patient`: Register a new patient record
- `grant-nurse-access`: Grant nurse access to patient records
- `add-medical-entry`: Add a medical entry to patient records
- `revoke-nurse-access`: Revoke nurse access to records

### Read-Only Functions
- `get-patient`: Retrieve patient information
- `get-medical-entry`: Get medical entry by ID
- `check-nurse-access`: Verify nurse access permissions

## Security Features

- Time-based access expiration
- Patient and owner authorization controls
- Encrypted data hash storage
- Access audit trail

## Testing

Run tests with Clarinet:
```bash
clarinet test