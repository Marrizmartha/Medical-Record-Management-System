;; PatientRecords - Secure Medical Records Management System
;; Manages patient medical records with nurse access control

(define-map patients
  { patient-id: uint }
  {
    patient-principal: principal,
    encrypted-data-hash: (string-ascii 64),
    created-by: principal,
    created-at: uint,
    last-updated: uint,
    is-active: bool
  }
)

(define-map nurse-access
  { nurse: principal, patient-id: uint }
  {
    access-level: (string-ascii 20),
    granted-by: principal,
    granted-at: uint,
    expires-at: uint
  }
)

(define-map medical-entries
  { entry-id: uint }
  {
    patient-id: uint,
    nurse-principal: principal,
    entry-hash: (string-ascii 64),
    entry-type: (string-ascii 30),
    timestamp: uint,
    is-critical: bool
  }
)

(define-data-var next-patient-id uint u1)
(define-data-var next-entry-id uint u1)

(define-constant contract-owner tx-sender)
(define-constant err-unauthorized (err u200))
(define-constant err-not-found (err u201))
(define-constant err-access-denied (err u202))
(define-constant err-expired-access (err u203))
(define-constant err-invalid-input (err u204))

;; Register a new patient
(define-public (register-patient 
  (patient-principal principal)
  (encrypted-data-hash (string-ascii 64))
)
  (let
    (
      (patient-id (var-get next-patient-id))
    )
    (asserts! (> (len encrypted-data-hash) u0) err-invalid-input)
    
    (map-set patients
      { patient-id: patient-id }
      {
        patient-principal: patient-principal,
        encrypted-data-hash: encrypted-data-hash,
        created-by: tx-sender,
        created-at: stacks-block-height,
        last-updated: stacks-block-height,
        is-active: true
      }
    )
    
    (var-set next-patient-id (+ patient-id u1))
    (ok patient-id)
  )
)

;; Grant nurse access to patient records
(define-public (grant-nurse-access
  (nurse principal)
  (patient-id uint)
  (access-level (string-ascii 20))
  (expires-at uint)
)
  (let
    (
      (patient-data (unwrap! (map-get? patients { patient-id: patient-id }) err-not-found))
    )
    (asserts! (or 
      (is-eq tx-sender (get patient-principal patient-data))
      (is-eq tx-sender contract-owner)
    ) err-unauthorized)
    (asserts! (> expires-at stacks-block-height) err-invalid-input)
    
    (map-set nurse-access
      { nurse: nurse, patient-id: patient-id }
      {
        access-level: access-level,
        granted-by: tx-sender,
        granted-at: stacks-block-height,
        expires-at: expires-at
      }
    )
    (ok true)
  )
)

;; Add medical entry
(define-public (add-medical-entry
  (patient-id uint)
  (entry-hash (string-ascii 64))
  (entry-type (string-ascii 30))
  (is-critical bool)
)
  (let
    (
      (patient-data (unwrap! (map-get? patients { patient-id: patient-id }) err-not-found))
      (access-data (map-get? nurse-access { nurse: tx-sender, patient-id: patient-id }))
      (entry-id (var-get next-entry-id))
    )
    (asserts! (get is-active patient-data) err-not-found)
    (asserts! (is-some access-data) err-access-denied)
    (asserts! (> (get expires-at (unwrap-panic access-data)) stacks-block-height) err-expired-access)
    (asserts! (> (len entry-hash) u0) err-invalid-input)
    
    (map-set medical-entries
      { entry-id: entry-id }
      {
        patient-id: patient-id,
        nurse-principal: tx-sender,
        entry-hash: entry-hash,
        entry-type: entry-type,
        timestamp: stacks-block-height,
        is-critical: is-critical
      }
    )
    
    ;; Update patient last-updated timestamp
    (map-set patients
      { patient-id: patient-id }
      (merge patient-data { last-updated: stacks-block-height })
    )
    
    (var-set next-entry-id (+ entry-id u1))
    (ok entry-id)
  )
)

;; Get patient information
(define-read-only (get-patient (patient-id uint))
  (map-get? patients { patient-id: patient-id })
)

;; Get medical entry
(define-read-only (get-medical-entry (entry-id uint))
  (map-get? medical-entries { entry-id: entry-id })
)

;; Check nurse access
(define-read-only (check-nurse-access (nurse principal) (patient-id uint))
  (match (map-get? nurse-access { nurse: nurse, patient-id: patient-id })
    access-data
    (> (get expires-at access-data) stacks-block-height)
    false
  )
)

;; Revoke nurse access
(define-public (revoke-nurse-access (nurse principal) (patient-id uint))
  (let
    (
      (patient-data (unwrap! (map-get? patients { patient-id: patient-id }) err-not-found))
      (access-data (unwrap! (map-get? nurse-access { nurse: nurse, patient-id: patient-id }) err-not-found))
    )
    (asserts! (or 
      (is-eq tx-sender (get patient-principal patient-data))
      (is-eq tx-sender contract-owner)
    ) err-unauthorized)
    
    (map-delete nurse-access { nurse: nurse, patient-id: patient-id })
    (ok true)
  )
)