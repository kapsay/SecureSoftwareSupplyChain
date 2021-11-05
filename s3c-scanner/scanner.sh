# -------------------------------
# Critical Vulnerability founder
# -------------------------------
image_name="gcr.io/$PROJECT_ID/$CLOUD_RUN_APP_NAME"
echo "----- $image_name"
digest_value=$(gcloud beta container images list-tags $image_name --format="table[no-heading](digest.slice(0:256).join(''))" --limit=1)
echo "----- $digest_value"
vuln_counter=$(gcloud beta container images describe $image_name@$digest_value --show-package-vulnerability --format="table[no-heading](package_vulnerability_summary.vulnerabilities.CRITICAL[].vulnerability.cvssScore)")
echo "----- $vuln_counter"

echo "* ---------------------------------------------------------------------------------------------------------------- *"
if [[ $vuln_counter == "" ]]
then
    echo "Continue - No Critical vulnerability found"
    gcloud beta container binauthz attestations sign-and-create --artifact-url $image_name@$digest_value --attestor=$BA_VULNERABILITY_ATTESTOR --attestor-project=$PROJECT_ID --keyversion="1" --keyversion-key=$BA_KEY --keyversion-location="us-central1" --keyversion-keyring=$BA_KEYRING --keyversion-project=$PROJECT_ID

    echo "Image attestation Binary Authorization is done..."
else
     
    echo "STOP!!! - Critical vulnerability found. Find vulnerability details at - "
    result_url="https://console.cloud.google.com/gcr/images/$PROJECT_ID/GLOBAL/$CLOUD_RUN_APP_NAME@$digest_value/details?tab=vulnz&project=$PROJECT_ID&organizationId=752378518739&supportedpurview=project&gcrVulnzListsize=30"
    echo "$result_url"
fi
echo "* ---------------------------------------------------------------------------------------------------------------- *"
