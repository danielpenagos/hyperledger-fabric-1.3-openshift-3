PROJECT=hyperledger

oc new-project $PROJECT


oc adm policy add-scc-to-user anyuid -z default -n $PROJECT
oc adm policy add-scc-to-user privileged -z default -n $PROJECT
------------

export CLUSTER_NAME="dpenagos-cl-saz"
export AWS_REGION="us-east-2"
export OIDC_PROVIDER=$(oc get authentication.config.openshift.io cluster -o json | jq -r .spec.serviceAccountIssuer| sed -e "s/^https:\/\///")
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export SCRATCH_DIR=/tmp/scratch
export AWS_PAGER=""
mkdir -p $SCRATCH_DIR

cat << EOF > $SCRATCH_DIR/efs-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "elasticfilesystem:DescribeAccessPoints",
        "elasticfilesystem:DescribeFileSystems",
        "elasticfilesystem:DescribeMountTargets",
        "elasticfilesystem:TagResource",
        "ec2:DescribeAvailabilityZones"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "elasticfilesystem:CreateAccessPoint"
      ],
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:RequestTag/efs.csi.aws.com/cluster": "true"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": "elasticfilesystem:DeleteAccessPoint",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/efs.csi.aws.com/cluster": "true"
        }
      }
    }
  ]
}
EOF

POLICY=$(aws iam create-policy --policy-name "${CLUSTER_NAME}-rosa-efs-csi" \
   --policy-document file://$SCRATCH_DIR/efs-policy.json \
   --query 'Policy.Arn' --output text) || \
   POLICY=$(aws iam list-policies \
   --query 'Policies[?PolicyName==`rosa-efs-csi`].Arn' \
   --output text)
echo $POLICY

cat <<EOF > $SCRATCH_DIR/TrustPolicy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": [
            "system:serviceaccount:openshift-cluster-csi-drivers:aws-efs-csi-driver-operator",
            "system:serviceaccount:openshift-cluster-csi-drivers:aws-efs-csi-driver-controller-sa"
          ]
        }
      }
    }
  ]
}
EOF

ROLE=$(aws iam create-role \
  --role-name "${CLUSTER_NAME}-aws-efs-csi-operator" \
  --assume-role-policy-document file://$SCRATCH_DIR/TrustPolicy.json \
  --query "Role.Arn" --output text)
echo $ROLE

aws iam attach-role-policy \
   --role-name "${CLUSTER_NAME}-aws-efs-csi-operator" \
   --policy-arn $POLICY

cat << EOF | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
 name: aws-efs-cloud-credentials
 namespace: openshift-cluster-csi-drivers
stringData:
  credentials: |-
    [default]
    role_arn = $ROLE
    web_identity_token_file = /var/run/secrets/openshift/serviceaccount/token
EOF


cat <<EOF | oc create -f -
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  generateName: openshift-cluster-csi-drivers-
  namespace: openshift-cluster-csi-drivers
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  labels:
    operators.coreos.com/aws-efs-csi-driver-operator.openshift-cluster-csi-drivers: ""
  name: aws-efs-csi-driver-operator
  namespace: openshift-cluster-csi-drivers
spec:
  channel: stable
  installPlanApproval: Automatic
  name: aws-efs-csi-driver-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF

cat <<EOF | oc apply -f -
apiVersion: operator.openshift.io/v1
kind: ClusterCSIDriver
metadata:
    name: efs.csi.aws.com
spec:
  managementState: Managed
EOF

watch oc get daemonset aws-efs-csi-driver-node -n openshift-cluster-csi-drivers

NODE=$(oc get nodes --selector=node-role.kubernetes.io/worker \
  -o jsonpath='{.items[0].metadata.name}')
VPC=$(aws ec2 describe-instances \
  --filters "Name=private-dns-name,Values=$NODE" \
  --query 'Reservations[*].Instances[*].{VpcId:VpcId}' \
  --region $AWS_REGION \
  | jq -r '.[0][0].VpcId')
CIDR=$(aws ec2 describe-vpcs \
  --filters "Name=vpc-id,Values=$VPC" \
  --query 'Vpcs[*].CidrBlock' \
  --region $AWS_REGION \
  | jq -r '.[0]')
SG=$(aws ec2 describe-instances --filters \
  "Name=private-dns-name,Values=$NODE" \
  --query 'Reservations[*].Instances[*].{SecurityGroups:SecurityGroups}' \
  --region $AWS_REGION \
  | jq -r '.[0][0].SecurityGroups[0].GroupId')
echo "CIDR - $CIDR,  SG - $SG"

aws ec2 authorize-security-group-ingress \
 --group-id $SG \
 --protocol tcp \
 --port 2049 \
 --cidr $CIDR | jq .

SUBNET=$(aws ec2 describe-subnets \
  --filters Name=vpc-id,Values=$VPC Name=tag:Name,Values='*-private*' \
  --query 'Subnets[*].{SubnetId:SubnetId}' \
  --region $AWS_REGION \
  | jq -r '.[0].SubnetId')
AWS_ZONE=$(aws ec2 describe-subnets --filters Name=subnet-id,Values=$SUBNET \
  --region $AWS_REGION | jq -r '.Subnets[0].AvailabilityZone')

EFS=$(aws efs create-file-system --creation-token efs-token-1 \
   --availability-zone-name $AWS_ZONE \
   --region $AWS_REGION \
   --encrypted | jq -r '.FileSystemId')
echo $EFS

MOUNT_TARGET=$(aws efs create-mount-target --file-system-id $EFS \
  --subnet-id $SUBNET --security-groups $SG \
  --region $AWS_REGION \
  | jq -r '.MountTargetId')
echo $MOUNT_TARGET

cat <<EOF | oc apply -f -
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: efs-sc
provisioner: efs.csi.aws.com
parameters:
  provisioningMode: efs-ap
  fileSystemId: $EFS
  directoryPerms: "700"
  gidRangeStart: "1000"
  gidRangeEnd: "2000"
  basePath: "/dynamic_provisioning"
EOF

cat <<EOF | oc apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pvc-efs-volume
spec:
  storageClassName: efs-sc
  accessModes:
    - ReadWriteMany
  resources:
    requests:
      storage: 5Gi
EOF
------------
oc apply -f kubernetes/fabric-pvc-nolabel.yaml -n $PROJECT

oc apply -f kubernetes/fabric-tools.yaml -n $PROJECT

oc -n $PROJECT exec -it fabric-tools -- mkdir -p /fabric/config

oc -n $PROJECT cp config/configtx.yaml fabric-tools:/fabric/config/
oc -n $PROJECT cp config/crypto-config.yaml fabric-tools:/fabric/config/
oc -n $PROJECT cp config/chaincode/ fabric-tools:/fabric/config/
oc -n $PROJECT cp instantiate_chaincode.sh fabric-tools:/fabric/config/

echo cryptogen

oc -n $PROJECT exec fabric-tools -- bash -c "cryptogen generate --config /fabric/config/crypto-config.yaml"
  
oc -n $PROJECT exec fabric-tools -- cp -r crypto-config /fabric/
  
oc -n $PROJECT exec fabric-tools -- bash -c 'for file in $(find /fabric/ -iname *_sk); do echo $file; dir=$(dirname $file); mv ${dir}/*_sk ${dir}/key.pem; done'


echo Generate genesis block
oc -n $PROJECT exec fabric-tools -- bash -c "cp /fabric/config/configtx.yaml /fabric/ && cd /fabric && configtxgen -profile FourOrgsOrdererGenesis -outputBlock genesis.block"


echo Create Anchor Peers
oc -n $PROJECT exec fabric-tools -- bash -c "cd /fabric && configtxgen -profile FourOrgsChannel -outputAnchorPeersUpdate ./Org1MSPanchors.tx -channelID channel1 -asOrg Org1MSP"
oc -n $PROJECT exec fabric-tools -- bash -c "cd /fabric && configtxgen -profile FourOrgsChannel -outputAnchorPeersUpdate ./Org2MSPanchors.tx -channelID channel1 -asOrg Org2MSP"
oc -n $PROJECT exec fabric-tools -- bash -c "cd /fabric && configtxgen -profile FourOrgsChannel -outputAnchorPeersUpdate ./Org3MSPanchors.tx -channelID channel1 -asOrg Org3MSP"
oc -n $PROJECT exec fabric-tools -- bash -c "cd /fabric && configtxgen -profile FourOrgsChannel -outputAnchorPeersUpdate ./Org4MSPanchors.tx -channelID channel1 -asOrg Org4MSP"


echo Fix permissions
oc -n $PROJECT exec fabric-tools -- bash -c "chmod a+rx /fabric/* -R"

echo Create Blockchain-ca deploy
oc -n $PROJECT apply -f kubernetes/blockchain-ca_deploy.yaml

echo Create service deploy
oc -n $PROJECT apply -f kubernetes/blockchain-ca_svc.yaml

echo Install zookeeper and kafka
oc apply -f kafka -n $PROJECT

echo Create Orderer
oc -n $PROJECT apply -f kubernetes/blockchain-orderer_deploy.yaml

echo Create orderer svc
oc expose deployment blockchain-orderer --port=31010 -n $PROJECT 

echo Create org1 and peer
oc -n $PROJECT apply -f kubernetes/blockchain-org1peer1_deploy.yaml
oc -n $PROJECT apply -f kubernetes/blockchain-org1peer2_deploy.yaml
oc -n $PROJECT apply -f kubernetes/blockchain-org1peer1_svc.yaml
oc -n $PROJECT apply -f kubernetes/blockchain-org1peer2_svc.yaml


  
echo Create org2 and peer
oc -n $PROJECT apply -f kubernetes/blockchain-org2peer1_deploy.yaml
oc -n $PROJECT apply -f kubernetes/blockchain-org2peer2_deploy.yaml
oc -n $PROJECT apply -f kubernetes/blockchain-org2peer1_svc.yaml
oc -n $PROJECT apply -f kubernetes/blockchain-org2peer2_svc.yaml

echo Create org3 and peer
oc -n $PROJECT apply -f kubernetes/blockchain-org3peer1_deploy.yaml
oc -n $PROJECT apply -f kubernetes/blockchain-org3peer2_deploy.yaml
oc -n $PROJECT apply -f kubernetes/blockchain-org3peer1_svc.yaml
oc -n $PROJECT apply -f kubernetes/blockchain-org3peer2_svc.yaml

echo Create org4 and peer
oc -n $PROJECT apply -f kubernetes/blockchain-org4peer1_deploy.yaml
oc -n $PROJECT apply -f kubernetes/blockchain-org4peer2_deploy.yaml
oc -n $PROJECT apply -f kubernetes/blockchain-org4peer1_svc.yaml
oc -n $PROJECT apply -f kubernetes/blockchain-org4peer2_svc.yaml



echo Create channel
oc -n $PROJECT exec fabric-tools -- bash -c 'export FABRIC_CFG_PATH=/fabric && export CHANNEL_NAME="channel1" && export ORDERER_URL="blockchain-orderer:31010" && export CORE_PEER_ADDRESSAUTODETECT="false" && export CORE_PEER_NETWORKID="nid1" && export CORE_PEER_LOCALMSPID="Org1MSP" && export CORE_PEER_MSPCONFIGPATH="/fabric/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp/" && cd /fabric && configtxgen -profile FourOrgsChannel -outputCreateChannelTx ${CHANNEL_NAME}.tx -channelID ${CHANNEL_NAME} && export FABRIC_CFG_PATH=/etc/hyperledger/fabric && peer channel create -o ${ORDERER_URL} -c ${CHANNEL_NAME} -f /fabric/${CHANNEL_NAME}.tx'




echo Join Org1MSP to Our Channel
oc -n $PROJECT exec fabric-tools -- bash -c 'export CHANNEL_NAME="channel1" && export CORE_PEER_NETWORKID="nid1" && export ORDERER_URL="blockchain-orderer:31010" && export FABRIC_CFG_PATH="/etc/hyperledger/fabric" && export CORE_PEER_LOCALMSPID="Org1MSP" && export CORE_PEER_MSPID="Org1MSP" && export CORE_PEER_MSPCONFIGPATH="/fabric/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp" && export CORE_PEER_ADDRESS="blockchain-org1peer1:30110" && peer channel fetch newest -o ${ORDERER_URL} -c ${CHANNEL_NAME} && peer channel join -b ${CHANNEL_NAME}_newest.block && rm -rf /${CHANNEL_NAME}_newest.block && export CORE_PEER_ADDRESS="blockchain-org1peer2:30110" && peer channel fetch newest -o ${ORDERER_URL} -c ${CHANNEL_NAME} && peer channel join -b ${CHANNEL_NAME}_newest.block && rm -rf /${CHANNEL_NAME}_newest.block'


echo Join Org2MSP to Our Channel
oc -n $PROJECT exec fabric-tools -- bash -c 'export CHANNEL_NAME="channel1" && export CORE_PEER_NETWORKID="nid1" && export ORDERER_URL="blockchain-orderer:31010" && export FABRIC_CFG_PATH="/etc/hyperledger/fabric" && export CORE_PEER_LOCALMSPID="Org2MSP" && export CORE_PEER_MSPID="Org2MSP" && export CORE_PEER_MSPCONFIGPATH="/fabric/crypto-config/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp" && export CORE_PEER_ADDRESS="blockchain-org2peer1:30110" && peer channel fetch newest -o ${ORDERER_URL} -c ${CHANNEL_NAME} && peer channel join -b ${CHANNEL_NAME}_newest.block && rm -rf /${CHANNEL_NAME}_newest.block && export CORE_PEER_ADDRESS="blockchain-org2peer2:30110" && peer channel fetch newest -o ${ORDERER_URL} -c ${CHANNEL_NAME} && peer channel join -b ${CHANNEL_NAME}_newest.block && rm -rf /${CHANNEL_NAME}_newest.block'

echo Join Org3MSP to Our Channel
oc -n $PROJECT exec fabric-tools -- bash -c 'export CHANNEL_NAME="channel1" && export CORE_PEER_NETWORKID="nid1" && export ORDERER_URL="blockchain-orderer:31010" && export FABRIC_CFG_PATH="/etc/hyperledger/fabric" && export CORE_PEER_LOCALMSPID="Org3MSP" && export CORE_PEER_MSPID="Org3MSP" && export CORE_PEER_MSPCONFIGPATH="/fabric/crypto-config/peerOrganizations/org3.example.com/users/Admin@org3.example.com/msp" && export CORE_PEER_ADDRESS="blockchain-org3peer1:30110" && peer channel fetch newest -o ${ORDERER_URL} -c ${CHANNEL_NAME} && peer channel join -b ${CHANNEL_NAME}_newest.block && rm -rf /${CHANNEL_NAME}_newest.block && export CORE_PEER_ADDRESS="blockchain-org3peer2:30110" && peer channel fetch newest -o ${ORDERER_URL} -c ${CHANNEL_NAME} && peer channel join -b ${CHANNEL_NAME}_newest.block && rm -rf /${CHANNEL_NAME}_newest.block'


echo Join Org4MSP to Our Channel
oc -n $PROJECT  exec fabric-tools -- bash -c 'export CHANNEL_NAME="channel1" && export CORE_PEER_NETWORKID="nid1" && export ORDERER_URL="blockchain-orderer:31010" && export FABRIC_CFG_PATH="/etc/hyperledger/fabric" && export CORE_PEER_LOCALMSPID="Org4MSP" && export CORE_PEER_MSPID="Org4MSP" && export CORE_PEER_MSPCONFIGPATH="/fabric/crypto-config/peerOrganizations/org4.example.com/users/Admin@org4.example.com/msp" && export CORE_PEER_ADDRESS="blockchain-org4peer1:30110" && peer channel fetch newest -o ${ORDERER_URL} -c ${CHANNEL_NAME} && peer channel join -b ${CHANNEL_NAME}_newest.block && rm -rf /${CHANNEL_NAME}_newest.block && export CORE_PEER_ADDRESS="blockchain-org4peer2:30110" && peer channel fetch newest -o ${ORDERER_URL} -c ${CHANNEL_NAME} && peer channel join -b ${CHANNEL_NAME}_newest.block && rm -rf /${CHANNEL_NAME}_newest.block'

echo Install Chaincode on Org1MSP
oc -n $PROJECT exec fabric-tools -- bash -c 'cp -r /fabric/config/chaincode $GOPATH/src/ && export CHAINCODE_NAME="cc" && export CHAINCODE_VERSION="1.0" && export FABRIC_CFG_PATH="/etc/hyperledger/fabric" && export CORE_PEER_MSPCONFIGPATH="/fabric/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp" && export CORE_PEER_LOCALMSPID="Org1MSP" && export CORE_PEER_ADDRESS="blockchain-org1peer1:30110" && peer chaincode install -n ${CHAINCODE_NAME} -v ${CHAINCODE_VERSION} -p chaincode_example02/ && export CORE_PEER_ADDRESS="blockchain-org1peer2:30110" && peer chaincode install -n ${CHAINCODE_NAME} -v ${CHAINCODE_VERSION} -p chaincode_example02/'


echo Install Chaincode on Org2MSP
oc -n $PROJECT exec fabric-tools -- bash -c 'cp -r /fabric/config/chaincode $GOPATH/src/ && export CHAINCODE_NAME="cc" && export CHAINCODE_VERSION="1.0" && export FABRIC_CFG_PATH="/etc/hyperledger/fabric" && export CORE_PEER_MSPCONFIGPATH="/fabric/crypto-config/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp" && export CORE_PEER_LOCALMSPID="Org2MSP" && export CORE_PEER_ADDRESS="blockchain-org2peer1:30110" && peer chaincode install -n ${CHAINCODE_NAME} -v ${CHAINCODE_VERSION} -p chaincode_example02/ && export CORE_PEER_ADDRESS="blockchain-org2peer2:30110" && peer chaincode install -n ${CHAINCODE_NAME} -v ${CHAINCODE_VERSION} -p chaincode_example02/'

echo Install Chaincode on Org3MSP
oc -n $PROJECT exec -it fabric-tools -- bash -c 'cp -r /fabric/config/chaincode $GOPATH/src/ && export CHAINCODE_NAME="cc" && export CHAINCODE_VERSION="1.0" && export FABRIC_CFG_PATH="/etc/hyperledger/fabric" && export CORE_PEER_MSPCONFIGPATH="/fabric/crypto-config/peerOrganizations/org3.example.com/users/Admin@org3.example.com/msp" && export CORE_PEER_LOCALMSPID="Org3MSP" && export CORE_PEER_ADDRESS="blockchain-org3peer1:30110" && peer chaincode install -n ${CHAINCODE_NAME} -v ${CHAINCODE_VERSION} -p chaincode_example02/ && export CORE_PEER_ADDRESS="blockchain-org3peer2:30110" && peer chaincode install -n ${CHAINCODE_NAME} -v ${CHAINCODE_VERSION} -p chaincode_example02/'

echo Install Chaincode on Org4MSP
oc -n $PROJECT exec -it fabric-tools -- bash -c 'cp -r /fabric/config/chaincode $GOPATH/src/ && export CHAINCODE_NAME="cc" && export CHAINCODE_VERSION="1.0" && export FABRIC_CFG_PATH="/etc/hyperledger/fabric" && export CORE_PEER_MSPCONFIGPATH="/fabric/crypto-config/peerOrganizations/org4.example.com/users/Admin@org4.example.com/msp" && export CORE_PEER_LOCALMSPID="Org4MSP" && export CORE_PEER_ADDRESS="blockchain-org4peer1:30110" && peer chaincode install -n ${CHAINCODE_NAME} -v ${CHAINCODE_VERSION} -p chaincode_example02/ && export CORE_PEER_ADDRESS="blockchain-org4peer2:30110" && peer chaincode install -n ${CHAINCODE_NAME} -v ${CHAINCODE_VERSION} -p chaincode_example02/'

echo Instantiate Chaincode
oc -n $PROJECT exec -it fabric-tools -- bash -c '/fabric/config/instantiate_chaincode.sh'
    register: chaincode_result
    failed_when: "'already exists' not in chaincode_result.stderr and chaincode_result.rc != 0"

echo Update channel from org1 to reflect Anchor Peers
    shell: |
      pod=$(oc get pods -n $PROJECT | grep blockchain-org1peer1 | awk '{print $1}')
      oc exec $pod -- peer channel update -f /fabric/Org1MSPanchors.tx -c channel1 -o blockchain-orderer:31010
    register: channel_org1
    failed_when: "'version 0, but got version 1' not in channel_org1.stderr and channel_org1.rc != 0"
  
echo Update channel from org2 to reflect Anchor Peers
    shell: |
      pod=$(oc get pods -n $PROJECT | grep blockchain-org2peer1 | awk '{print $1}')
      oc exec $pod -- peer channel update -f /fabric/Org2MSPanchors.tx -c channel1 -o blockchain-orderer:31010
    register: channel_org2
    failed_when: "'version 0, but got version 1' not in channel_org2.stderr and channel_org2.rc != 0"

echo Update channel from org3 to reflect Anchor Peers
    shell: |
      pod=$(oc get pods -n $PROJECT | grep blockchain-org3peer1 | awk '{print $1}')
      oc exec $pod -- peer channel update -f /fabric/Org3MSPanchors.tx -c channel1 -o blockchain-orderer:31010
    register: channel_org3
    failed_when: "'version 0, but got version 1' not in channel_org3.stderr and channel_org3.rc != 0"

echo Update channel from org4 to reflect Anchor Peers
    shell: |
      pod=$(oc get pods -n $PROJECT | grep blockchain-org4peer1 | awk '{print $1}')
      oc exec $pod -- peer channel update -f /fabric/Org4MSPanchors.tx -c channel1 -o blockchain-orderer:31010
    register: channel_org4
    failed_when: "'version 0, but got version 1' not in channel_org4.stderr and channel_org4.rc != 0"
  
echo Deploy Hyperledger Explorer Database
    shell: "oc apply -f kubernetes/blockchain-explorer-db_deploy.yaml -n $PROJECT

  - name: Create Explorer Service
    shell: "oc apply -f kubernetes/blockchain-explorer-db_svc.yaml -n $PROJECT

  - name: Wait for postgresql to be ready
    shell: oc get po -n $PROJECT | grep -i blockchain-explorer-db
    register: postgresql_explorer
    until: postgresql_explorer.stdout.find("Running") != -1
    retries: 60
    delay: 40

  - name: Populate database
    shell: |
      pod=$(oc get pods | grep blockchain-explorer-db | awk '{print $1}')
      oc -n $PROJECT exec $pod -- bash -c 'mkdir -p /fabric/config/explorer/db/ && mkdir -p /fabric/config/explorer/app/ && cd /fabric/config/explorer/db/ && wget https://raw.githubusercontent.com/hyperledger/blockchain-explorer/master/app/persistence/fabric/postgreSQL/db/createdb.sh -O createdb.sh && wget https://raw.githubusercontent.com/hyperledger/blockchain-explorer/master/app/persistence/fabric/postgreSQL/db/explorerpg.sql -O explorerpg.sql && wget https://raw.githubusercontent.com/hyperledger/blockchain-explorer/master/app/persistence/fabric/postgreSQL/db/processenv.js -O processenv.js && wget https://raw.githubusercontent.com/hyperledger/blockchain-explorer/master/app/persistence/fabric/postgreSQL/db/updatepg.sql -O updatepg.sql && apk update && apk add jq ; apk add nodejs ; apk add sudo ; rm -rf /var/cache/apk/* && chmod +x ./createdb.sh && ./createdb.sh'

  - name: Copy network file
    shell: oc -n $PROJECT cp config/explorer/app/config.json fabric-tools:/fabric/config/explorer/app/
    ignore_errors: true

  - name: Copy run.sh
    shell: chmod +x config/explorer/app/run.sh && oc -n $PROJECT cp config/explorer/app/run.sh fabric-tools:/fabric/config/explorer/app/
    ignore_errors: true
    
  - name: Deploy explorer
    shell: "oc apply -f kubernetes/blockchain-explorer-app_deploy.yaml -n {{ project_name }}"

  - name: Create explorer svc
    shell: "oc expose deployment blockchain-explorer-app --port=8080 -n {{ project_name }} || echo 'ja existe'"

  - name: Create explorer route
    shell: "oc expose svc/blockchain-explorer-app -n {{ project_name }} || echo 'ja existe'"

  - name: Remove helper pod
    shell: "oc delete -f kubernetes/fabric-tools.yaml -n {{ project_name }}"