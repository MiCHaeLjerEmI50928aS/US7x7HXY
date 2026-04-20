# Step 1: Create the Master IAM Role

This is the most important foundational step. We will create a single **IAM (Identity and Access Management) Role** that will act as a "security badge" for all our future Lambda functions. This role will grant them the precise permissions needed to interact with other AWS services like S3, Rekognition, and Transcribe.

**Role Name:** `AI-Playground-Role`

---

### ► Step-by-Step Instructions

#### 1. Navigate to the IAM Dashboard

- Log in to your **AWS Management Console**.
- In the top search bar, type `IAM` and select it from the results.

#### 2. Start the Role Creation Process

- In the IAM dashboard, click on **"Roles"** in the left-hand navigation pane.
- Click the blue **"Create role"** button.

#### 3. Select the Trusted Entity

This step tells AWS which service will be "wearing" this security badge.

- For **"Trusted entity type,"** select **"AWS service"**.
- Under **"Use case,"** choose **"Lambda"**. This specifies that we are creating a role for a Lambda function to use.
- Click **"Next"**.

#### 4. Attach the Permission Policies

This is where we grant the specific permissions. You will use the search bar to find and add each of the seven policies listed below.

- In the search box under **"Permissions policies,"** search for the first policy name (`AWSLambdaBasicExecutionRole`).
- Check the box next to it in the list.
- Clear the search box and repeat the process for all seven policies.

**Checklist of Policies to Attach:**

- `AWSLambdaBasicExecutionRole`
  - _(**Why?** Allows the function to write logs to CloudWatch for debugging.)_
- `AmazonS3FullAccess`
  - _(**Why?** Allows creating secure upload URLs and reading/writing audio files.)_
- `AmazonTranscribeFullAccess`
  - _(**Why?** Allows starting and managing audio transcription jobs.)_
- `AmazonRekognitionReadOnlyAccess`
  - _(**Why?** Allows the function to call the Rekognition image analysis API.)_
- `AmazonTextractFullAccess`
  - _(**Why?** Allows the function to call the Textract OCR API.)_
- `ComprehendFullAccess`
  - _(**Why?** Allows the function to call the Comprehend entity detection API.)_
- `AmazonBedrockFullAccess`
  - _(**Why?** For our future "Image to Summary" feature using generative AI.)_

After you have selected all seven policies, click the **"Next"** button.

#### 5. Name and Create the Role

- On the final screen, enter the **Role name**: `AI-Playground-Role`
- You can leave the description blank or add a simple one like, "Grants necessary permissions for the AI Playground application's Lambda functions."
- Scroll to the bottom and click the **"Create role"** button.

---

### ✅ Success!

You have now successfully created the `AI-Playground-Role`. This single role contains all the permissions our backend services will need. We are now ready to create our first Lambda function.
