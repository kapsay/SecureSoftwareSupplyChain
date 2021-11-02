provider "google-beta" {
  project     = var.POLICY_PROJECT_ID
  region      = var.POLICY_REGION
}

terraform {
  backend "gcs" {
    bucket = "sw-supply-chain-demo-tfstate"
    prefix = "env"
  }
}

# Create Cloud KMS key ring
resource "google_kms_key_ring" "kms_ring" {
#    depends_on = [
#        google_binary_authorization_policy.policy
#    ]    
    project  = var.POLICY_PROJECT_ID
    name     = var.BA_KEYRING
    location = var.POLICY_REGION
}

# Create an asymmetric Cloud KMS key that will be used to sign and 
# verify vulnerability scan attestations
resource "google_kms_crypto_key" "kms_key" {
    depends_on = [
      google_kms_key_ring.kms_ring
    ]
    name            = var.BA_KEY
    key_ring        = google_kms_key_ring.kms_ring.id
    purpose  = "ASYMMETRIC_SIGN"
  
    version_template {
        algorithm = "RSA_SIGN_PKCS1_4096_SHA512"
    }
}

# Create a Container Analysis Note
resource "google_container_analysis_note" "note" {
#    depends_on = [google_binary_authorization_policy.policy]
    name = var.BA_NOTE_NAME
    project = var.POLICY_PROJECT_ID  
    attestation_authority {
      hint {
        human_readable_name = "No Vulnerability Note"
      }
    }
}

resource "google_project_iam_member" "permission_iam" {
    depends_on = [
      google_kms_crypto_key.kms_key
    ]
    project = var.POLICY_PROJECT_ID
    role    = "roles/containeranalysis.notes.occurrences.viewer"
    member  = "serviceAccount:${var.CLOUD_BUILD_SA}"
}

data "google_kms_crypto_key_version" "key_version" {
  crypto_key = google_kms_crypto_key.kms_key.id
}

#Add the public key for the attestor's signing key
resource "google_binary_authorization_attestor" "attestor" {
    depends_on = [
      google_container_analysis_note.note
    ]

    name = var.BA_VULNERABILITY_ATTESTOR
    description = "No vulnerability attestor"
    project = var.POLICY_PROJECT_ID
    attestation_authority_note {
    #note_reference = google_container_analysis_note.ba-vulnerability-note.name
      note_reference = "projects/${var.POLICY_PROJECT_ID}/notes/${var.BA_NOTE_ID}"
      public_keys {
        id = data.google_kms_crypto_key_version.key_version.id
        pkix_public_key {
          public_key_pem      = data.google_kms_crypto_key_version.key_version.public_key[0].pem
          signature_algorithm = data.google_kms_crypto_key_version.key_version.public_key[0].algorithm
        }
      }
    }
}

resource "google_binary_authorization_policy" "policy" {
    depends_on = [
      google_binary_authorization_attestor.attestor
    ]
    project  = var.POLICY_PROJECT_ID
    admission_whitelist_patterns {
      name_pattern  = "gcr.io/sw-supply-chain-demo/hello"
    }
    admission_whitelist_patterns {
      name_pattern  = "gcr.io/google_containers/*"
    }
    admission_whitelist_patterns {
      name_pattern  = "k8s.gcr.io/*"
    }
    admission_whitelist_patterns {
      name_pattern  = "gke.gcr.io/*"
    }
    admission_whitelist_patterns {
      name_pattern  = "gcr.io/stackdriver-agents/*"
    }
    admission_whitelist_patterns {
      name_pattern  = "gcr.io/google-containers/*"
    }

    default_admission_rule {
        evaluation_mode  = "REQUIRE_ATTESTATION"
        enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"
        require_attestations_by = [google_binary_authorization_attestor.attestor.name]
    }

    global_policy_evaluation_mode = "ENABLE"
} 



# Assign Cloud Build service account permission to view and attach note to container images
resource "google_binary_authorization_attestor_iam_member" "member_viewer" {
    depends_on = [
      google_container_analysis_note.note,
      google_binary_authorization_attestor.attestor
    ]
    project = var.POLICY_PROJECT_ID
    attestor = google_binary_authorization_attestor.attestor.name
    
    role = "roles/binaryauthorization.attestorsViewer"
    member = "serviceAccount:${var.CLOUD_BUILD_SA}"
}

resource "google_kms_key_ring_iam_member" "key_ring_iam" {
  depends_on = [google_kms_key_ring.kms_ring]
  key_ring_id = google_kms_key_ring.kms_ring.id
  role        = "roles/cloudkms.signerVerifier"
  member      = "serviceAccount:${var.CLOUD_BUILD_SA}"
}

# Grant the Cloud Build service account permission to view and attach the note to container images
resource "null_resource" "ba-grant-role-note" {
  depends_on = [null_resource.ba-analysis-note]
  provisioner "local-exec" {
    environment = {
      POLICY_PROJECT_ID = var.POLICY_PROJECT_ID
      BINAUTH_NOTE_ID = var.BA_NOTE_ID
      CLOUD_BUILD_SA_EMAIL = var.CLOUD_BUILD_SA
    }
    command  = "sh notePermission.sh"
  }
}


/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/*
resource "google_binary_authorization_attestor" "attestor" {
    depends_on = []
    name = "no-vulnerability-attestor"
    attestation_authority_note {
      note_reference = google_container_analysis_note.note.name
    }
}
*/
/*
#Grant the Cloud Build service account permission to verify attestations made by vulnz-attestor
resource "google_binary_authorization_attestor_iam_member" "ba-member" {
  depends_on = [google_binary_authorization_attestor.ba-attestor]
  project = var.POLICY_PROJECT_ID
  attestor = google_binary_authorization_attestor.ba-attestor.name
  role = "roles/binaryauthorization.attestorsViewer"
  member = "serviceAccount:${var.CLOUD_BUILD_SA}"
}
*/
