curl "https://containeranalysis.googleapis.com/v1/projects/${POLICY_PROJECT_ID}/notes/${BA_NOTE_ID}:setIamPolicy" \
--request POST \
--header "Content-Type: application/json" \
--header "Authorization: Bearer $(gcloud auth print-access-token)" \
--header "X-Goog-User-Project: ${POLICY_PROJECT_ID}" \
--data-binary @- <<EOF
    {
    "resource": "projects/${POLICY_PROJECT_ID}/notes/${BA_NOTE_ID}",
    "policy": {
        "bindings": [
        {
            "role": "roles/containeranalysis.notes.occurrences.viewer",
            "members": [
            "serviceAccount:${CLOUD_BUILD_SA}"
            ]
        },
        {
            "role": "roles/containeranalysis.notes.attacher",
            "members": [
            "serviceAccount:${CLOUD_BUILD_SA}"
            ]
        }
        ]
    }
    }
EOF