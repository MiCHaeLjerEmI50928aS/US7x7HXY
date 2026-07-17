/**
 * AWS Cloud Roadmap — Panduan Belajar Cloud Computing
 * script.js
 *
 * Isi:
 *  1. Data roadmap (Array of Objects)
 *  2. Render timeline cards
 *  3. Modal open/close
 *  4. Accordion logic
 *  5. Intersection Observer (entrance animation)
 */

/* ============================================================
   1. DATA ROADMAP
   Setiap stage memiliki:
   - id, title, badge (kategori), badgeClass, description
   - topics: array of { name, explanation, ytKeyword, docUrl }
   ============================================================ */
const roadmap = [
  {
    id: 0,
    title: "Pra-Cloud Fundamental",
    badge: "Fundamental",
    badgeClass: "badge-fundamental",
    description: "Membangun pondasi kuat tentang jaringan komputer, Linux CLI, dan alat kerja dasar sebelum masuk ke dunia cloud.",
    topics: [
      {
        name: "Dasar Jaringan Komputer",
        explanation: "Pahami cara data bergerak antar perangkat melalui jaringan: konsep OSI model, protokol komunikasi, dan cara kerja internet secara umum.",
        ytKeyword: "dasar jaringan komputer pemula",
        docUrl: ""
      },
      {
        name: "IP Address & Subnetting / CIDR",
        explanation: "IP Address adalah alamat unik setiap perangkat di jaringan. Subnetting membagi jaringan besar menjadi subnet kecil. CIDR (mis. /24) menentukan berapa banyak host yang tersedia.",
        ytKeyword: "IP address subnetting CIDR tutorial",
        docUrl: "https://aws.amazon.com/vpc/faqs/"
      },
      {
        name: "Routing Dasar",
        explanation: "Routing adalah proses mengarahkan paket data dari satu jaringan ke jaringan lain menggunakan router. Di AWS, konsep ini berhubungan langsung dengan Route Table VPC.",
        ytKeyword: "routing dasar jaringan tutorial",
        docUrl: ""
      },
      {
        name: "DNS (Domain Name System)",
        explanation: "DNS menerjemahkan nama domain (misal: example.com) menjadi IP Address. Di AWS, layanan DNS dikelola melalui Route 53.",
        ytKeyword: "DNS domain name system explained",
        docUrl: "https://aws.amazon.com/route53/what-is-dns/"
      },
      {
        name: "Perbedaan TCP dan UDP",
        explanation: "TCP (Transmission Control Protocol) menjamin pengiriman data secara berurutan dan terpercaya. UDP lebih cepat namun tidak ada garansi pengiriman. Penting dipahami untuk security group.",
        ytKeyword: "perbedaan TCP UDP jaringan",
        docUrl: ""
      },
      {
        name: "Port Penting: 22, 80, 443, 3306",
        explanation: "Port 22 = SSH, Port 80 = HTTP, Port 443 = HTTPS, Port 3306 = MySQL. Konfigurasi port ini sangat krusial saat mengatur Security Group di AWS.",
        ytKeyword: "port jaringan 22 80 443 3306 fungsi",
        docUrl: ""
      },
      {
        name: "Dasar Linux CLI",
        explanation: "Mayoritas server AWS berjalan di Linux. Kuasai perintah dasar: ls, cd, mkdir, rm, cp, mv, cat, nano, grep, chmod, chown, sudo, dan ps.",
        ytKeyword: "perintah dasar Linux CLI terminal pemula",
        docUrl: ""
      },
      {
        name: "Navigasi File & Folder di Linux",
        explanation: "Pahami struktur direktori Linux: /etc (konfigurasi), /var/www (web files), /home (user), /tmp (sementara). Gunakan pwd, ls -la, dan cd untuk navigasi.",
        ytKeyword: "navigasi file folder Linux command line",
        docUrl: ""
      },
      {
        name: "Manajemen Permission File Linux",
        explanation: "Permission Linux (rwx) mengontrol siapa bisa baca/tulis/eksekusi file. Gunakan chmod (misal: chmod 755) dan chown untuk mengatur kepemilikan file aplikasi web.",
        ytKeyword: "linux file permission chmod chown tutorial",
        docUrl: ""
      },
      {
        name: "SSH Remote Server menggunakan PuTTY",
        explanation: "PuTTY adalah client SSH untuk Windows. Digunakan untuk mengakses EC2 instance dari PC lokal. Butuh file .ppk (private key) yang dibuat dengan PuTTYgen.",
        ytKeyword: "SSH PuTTY EC2 AWS tutorial",
        docUrl: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/putty.html"
      },
      {
        name: "Transfer File Server menggunakan WinSCP",
        explanation: "WinSCP adalah tool SFTP/SCP berbasis GUI untuk transfer file antara PC lokal dan server Linux (EC2). Sangat berguna untuk upload file proyek ke server.",
        ytKeyword: "WinSCP transfer file EC2 AWS tutorial",
        docUrl: ""
      },
      {
        name: "Dasar Git dan GitHub",
        explanation: "Git adalah version control system. GitHub adalah platform hosting repository. Kuasai: git init, git clone, git add, git commit, git push, git pull untuk deploy kode ke EC2.",
        ytKeyword: "belajar Git GitHub dasar pemula bahasa Indonesia",
        docUrl: "https://docs.github.com/en/get-started"
      }
    ]
  },
  {
    id: 1,
    title: "Perencanaan & Desain Arsitektur",
    badge: "Design",
    badgeClass: "badge-design",
    description: "Sebelum membangun, rancang arsitektur cloud yang scalable, aman, dan hemat biaya menggunakan Draw.io dan AWS Pricing Calculator.",
    topics: [
      {
        name: "Memahami Kebutuhan Pengguna & Tujuan Proyek",
        explanation: "Identifikasi siapa pengguna sistem, fitur apa yang dibutuhkan, berapa banyak traffic yang diantisipasi, dan apa SLA (Service Level Agreement) yang diinginkan.",
        ytKeyword: "analisis kebutuhan sistem cloud computing",
        docUrl: ""
      },
      {
        name: "Desain Arsitektur Cloud dengan Draw.io",
        explanation: "Draw.io (diagrams.net) menyediakan ikon resmi AWS untuk membuat diagram arsitektur. Buat diagram yang menunjukkan VPC, subnet, EC2, RDS, Load Balancer, dan aliran data.",
        ytKeyword: "draw.io AWS architecture diagram tutorial",
        docUrl: "https://aws.amazon.com/architecture/icons/"
      },
      {
        name: "Memilih Layanan AWS Sesuai Kebutuhan",
        explanation: "Pelajari kapan menggunakan EC2 vs Lambda, RDS vs DynamoDB, ECS vs Elastic Beanstalk. Pemilihan layanan mempengaruhi biaya, skalabilitas, dan kemudahan pengelolaan.",
        ytKeyword: "memilih layanan AWS yang tepat",
        docUrl: "https://aws.amazon.com/products/"
      },
      {
        name: "Konsep High Availability",
        explanation: "High Availability (HA) memastikan sistem tetap berjalan meski ada kegagalan komponen. Implementasi dengan Multi-AZ deployment, Load Balancer, dan Auto Scaling.",
        ytKeyword: "high availability AWS multi AZ explained",
        docUrl: "https://docs.aws.amazon.com/whitepapers/latest/real-time-communication-on-aws/high-availability-and-scalability-on-aws.html"
      },
      {
        name: "Konsep Scalability",
        explanation: "Scalability = kemampuan sistem menambah kapasitas sesuai kebutuhan. Horizontal scaling (tambah instance) lebih disukai di cloud dibanding vertical scaling (upgrade spek).",
        ytKeyword: "scalability horizontal vertical scaling AWS",
        docUrl: ""
      },
      {
        name: "Konsep Security by Design",
        explanation: "Keamanan harus dibangun sejak awal, bukan ditambahkan belakangan. Prinsipnya: least privilege, encrypt data at rest & in transit, dan segmentasi jaringan.",
        ytKeyword: "security by design cloud AWS best practice",
        docUrl: "https://aws.amazon.com/compliance/shared-responsibility-model/"
      },
      {
        name: "Konsep Backup Strategy",
        explanation: "Strategi backup meliputi: frekuensi backup, retention period, cross-region backup untuk disaster recovery, dan pengujian restore. AWS Backup mengotomatiskan proses ini.",
        ytKeyword: "backup strategy AWS cloud disaster recovery",
        docUrl: "https://aws.amazon.com/backup/"
      },
      {
        name: "Estimasi Biaya dengan AWS Pricing Calculator",
        explanation: "AWS Pricing Calculator (calculator.aws) membantu estimasi biaya sebelum deployment. Masukkan EC2 type, storage, transfer data, dan layanan lain untuk mendapat perkiraan biaya bulanan.",
        ytKeyword: "AWS pricing calculator estimasi biaya tutorial",
        docUrl: "https://calculator.aws/pricing/2/home"
      },
      {
        name: "Dokumentasi Rancangan Teknis",
        explanation: "Dokumentasikan arsitektur dalam bentuk dokumen tertulis mencakup: diagram, deskripsi layanan, konfigurasi jaringan, estimasi biaya, dan justifikasi setiap keputusan teknis.",
        ytKeyword: "dokumentasi teknis arsitektur cloud",
        docUrl: ""
      }
    ]
  },
  {
    id: 2,
    title: "Keamanan Dasar AWS",
    badge: "Security",
    badgeClass: "badge-security",
    description: "Amankan infrastruktur AWS dengan IAM, Security Group, enkripsi, dan prinsip keamanan cloud modern.",
    topics: [
      {
        name: "AWS IAM — User, Group, Role, Policy",
        explanation: "IAM (Identity and Access Management) mengontrol siapa boleh melakukan apa di AWS. User = individu, Group = kumpulan user, Role = identitas sementara untuk layanan, Policy = dokumen izin JSON.",
        ytKeyword: "AWS IAM tutorial bahasa Indonesia",
        docUrl: "https://docs.aws.amazon.com/iam/latest/userguide/introduction.html"
      },
      {
        name: "Prinsip Least Privilege",
        explanation: "Berikan hanya izin minimum yang diperlukan. Jangan beri akses AdministratorAccess kecuali benar-benar dibutuhkan. Review dan audit permission secara berkala.",
        ytKeyword: "least privilege principle AWS IAM",
        docUrl: ""
      },
      {
        name: "Larangan Penggunaan Root Account",
        explanation: "Root account memiliki akses penuh tanpa batas. Gunakan hanya untuk task yang benar-benar membutuhkannya (misal: billing). Buat IAM user terpisah untuk pekerjaan sehari-hari.",
        ytKeyword: "AWS root account best practice IAM user",
        docUrl: "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
      },
      {
        name: "Multi-Factor Authentication (MFA)",
        explanation: "MFA menambahkan lapisan keamanan kedua (selain password) berupa kode OTP dari aplikasi authenticator. Aktifkan MFA untuk root account dan semua IAM user dengan akses penting.",
        ytKeyword: "AWS MFA multi factor authentication setup",
        docUrl: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
      },
      {
        name: "Security Group sebagai Firewall Instance",
        explanation: "Security Group adalah firewall virtual di level instance EC2. Konfigurasi inbound rules (traffic masuk) dan outbound rules (traffic keluar) berdasarkan port, protokol, dan sumber IP.",
        ytKeyword: "AWS security group tutorial inbound outbound rules",
        docUrl: "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"
      },
      {
        name: "IAM Role untuk EC2",
        explanation: "Daripada menyimpan access key di dalam EC2, gunakan IAM Role yang di-attach ke instance. EC2 otomatis mendapat credential sementara untuk mengakses layanan AWS lain seperti S3.",
        ytKeyword: "IAM role EC2 tutorial AWS",
        docUrl: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html"
      },
      {
        name: "AWS Certificate Manager (ACM)",
        explanation: "ACM menyediakan dan mengelola sertifikat SSL/TLS secara gratis untuk domain yang digunakan di AWS (CloudFront, Load Balancer, API Gateway). Aktifkan HTTPS agar koneksi terenkripsi.",
        ytKeyword: "AWS Certificate Manager ACM SSL HTTPS tutorial",
        docUrl: "https://docs.aws.amazon.com/acm/latest/userguide/acm-overview.html"
      },
      {
        name: "AWS Secrets Manager",
        explanation: "Secrets Manager menyimpan dan merotasi kredensial sensitif (password database, API key) secara aman. Aplikasi mengambil secret via API, bukan hardcode di kode sumber.",
        ytKeyword: "AWS Secrets Manager tutorial credential management",
        docUrl: "https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html"
      },
      {
        name: "AWS Key Management Service (KMS)",
        explanation: "KMS mengelola kunci enkripsi untuk mengamankan data di S3, RDS, EBS, dan layanan lain. Gunakan KMS untuk enkripsi data at-rest sesuai kebutuhan keamanan proyek.",
        ytKeyword: "AWS KMS key management service tutorial",
        docUrl: "https://docs.aws.amazon.com/kms/latest/developerguide/overview.html"
      },
      {
        name: "Pengujian Keamanan Dasar",
        explanation: "Verifikasi konfigurasi keamanan: cek apakah port yang tidak diperlukan tertutup, root account tidak digunakan aktif, MFA aktif, dan tidak ada bucket S3 yang public tanpa sengaja.",
        ytKeyword: "AWS security testing checklist best practice",
        docUrl: ""
      }
    ]
  },
  {
    id: 3,
    title: "Infrastruktur Inti AWS",
    badge: "AWS Core",
    badgeClass: "badge-core",
    description: "Bangun jaringan virtual (VPC), launch EC2, konfigurasi DNS dengan Route 53, dan distribusi konten dengan CloudFront.",
    topics: [
      {
        name: "Membuat VPC (Virtual Private Cloud)",
        explanation: "VPC adalah jaringan virtual terisolasi di AWS. Tentukan CIDR block (misal: 10.0.0.0/16), yang akan menjadi ruang alamat IP seluruh infrastruktur proyek.",
        ytKeyword: "AWS VPC create tutorial bahasa Indonesia",
        docUrl: "https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html"
      },
      {
        name: "Public Subnet & Private Subnet",
        explanation: "Public Subnet = subnet yang bisa diakses dari internet (untuk web server, load balancer). Private Subnet = subnet tanpa akses internet langsung (untuk database, application server).",
        ytKeyword: "AWS public private subnet VPC tutorial",
        docUrl: ""
      },
      {
        name: "Internet Gateway",
        explanation: "Internet Gateway (IGW) adalah komponen yang memungkinkan komunikasi antara VPC dan internet. Attach IGW ke VPC, lalu tambahkan route 0.0.0.0/0 → IGW di public subnet route table.",
        ytKeyword: "AWS internet gateway VPC setup tutorial",
        docUrl: "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html"
      },
      {
        name: "Route Table",
        explanation: "Route Table menentukan kemana traffic diarahkan. Public subnet route table → IGW. Private subnet route table → NAT Gateway. Satu subnet hanya bisa asosiasi dengan satu route table.",
        ytKeyword: "AWS route table VPC tutorial",
        docUrl: ""
      },
      {
        name: "NAT Gateway / NAT Instance",
        explanation: "NAT Gateway memungkinkan instance di private subnet mengakses internet (untuk update paket) tanpa bisa diakses dari internet. NAT Instance lebih murah tapi butuh konfigurasi manual.",
        ytKeyword: "AWS NAT gateway private subnet tutorial",
        docUrl: "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html"
      },
      {
        name: "Meluncurkan EC2 Linux",
        explanation: "EC2 (Elastic Compute Cloud) adalah virtual server. Pilih AMI (Amazon Linux 2/Ubuntu), instance type (t3.micro untuk free tier), configure security group, dan download key pair (.pem).",
        ytKeyword: "launch EC2 instance AWS tutorial bahasa Indonesia",
        docUrl: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EC2_GetStarted.html"
      },
      {
        name: "Elastic IP",
        explanation: "Elastic IP adalah IP publik statis yang tidak berubah meski EC2 di-restart. Alokasikan Elastic IP dan associate ke EC2 instance agar IP tetap konsisten untuk DNS mapping.",
        ytKeyword: "AWS Elastic IP EC2 tutorial",
        docUrl: ""
      },
      {
        name: "Security Group — Port 22, 80, 443, 3306",
        explanation: "Konfigurasi inbound rules: port 22 (SSH) hanya dari IP kantor/spesifik, port 80 & 443 dari 0.0.0.0/0 (publik), port 3306 hanya dari security group aplikasi (bukan publik).",
        ytKeyword: "AWS security group port 22 80 443 3306 setup",
        docUrl: ""
      },
      {
        name: "Instalasi Web Server Apache / Nginx",
        explanation: "Di EC2 Amazon Linux: sudo yum install httpd -y (Apache) atau sudo amazon-linux-extras install nginx1 -y. Aktifkan dengan sudo systemctl enable --now httpd/nginx.",
        ytKeyword: "install Apache Nginx EC2 Amazon Linux tutorial",
        docUrl: ""
      },
      {
        name: "Route 53 untuk DNS",
        explanation: "Route 53 adalah layanan DNS AWS. Buat hosted zone untuk domain, tambahkan A record yang mengarah ke Elastic IP atau Load Balancer. Dukung health check dan routing policy.",
        ytKeyword: "AWS Route 53 DNS setup tutorial",
        docUrl: "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/Welcome.html"
      },
      {
        name: "CloudFront sebagai CDN",
        explanation: "CloudFront adalah CDN (Content Delivery Network) AWS dengan 400+ edge location global. Distribusikan konten statis (gambar, CSS, JS) lebih cepat ke pengguna. Bisa terminate SSL.",
        ytKeyword: "AWS CloudFront CDN setup tutorial",
        docUrl: "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Introduction.html"
      },
      {
        name: "API Gateway Dasar",
        explanation: "API Gateway memungkinkan pembuatan, pengelolaan, dan keamanan API RESTful. Bisa diintegrasikan dengan Lambda (serverless) atau EC2 backend. Tangani rate limiting dan autentikasi.",
        ytKeyword: "AWS API Gateway tutorial REST API",
        docUrl: "https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html"
      }
    ]
  },
  {
    id: 4,
    title: "Storage & Database",
    badge: "Storage",
    badgeClass: "badge-storage",
    description: "Kelola penyimpanan objek (S3), block storage (EBS), dan database relasional (RDS MySQL) dengan strategi backup yang solid.",
    topics: [
      {
        name: "Amazon S3 Bucket",
        explanation: "S3 (Simple Storage Service) menyimpan objek (file) dengan kapasitas tidak terbatas. Setiap objek diakses via URL unik. Cocok untuk aset statis, backup, dan hosting website statis.",
        ytKeyword: "AWS S3 bucket tutorial bahasa Indonesia",
        docUrl: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html"
      },
      {
        name: "Bucket Policy & Akses Publik/Privat",
        explanation: "Bucket Policy adalah dokumen JSON yang menentukan siapa bisa mengakses isi bucket. Untuk website statis gunakan public read. Untuk backup gunakan private. Blokir akses publik secara default.",
        ytKeyword: "AWS S3 bucket policy public private access",
        docUrl: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-policy-language-overview.html"
      },
      {
        name: "EBS Volume (Elastic Block Store)",
        explanation: "EBS adalah penyimpanan block-level untuk EC2, seperti hard disk virtual. Bisa di-attach/detach dari instance. Gunakan untuk data persisten aplikasi. Tersedia tipe gp3, io1, st1.",
        ytKeyword: "AWS EBS volume tutorial attach EC2",
        docUrl: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AmazonEBS.html"
      },
      {
        name: "Backup Data & AWS Backup",
        explanation: "AWS Backup mengotomatiskan backup lintas layanan (EC2, RDS, EFS, DynamoDB). Buat backup plan dengan jadwal dan retention policy. Test restore secara berkala untuk memastikan backup valid.",
        ytKeyword: "AWS Backup service tutorial automated backup",
        docUrl: "https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html"
      },
      {
        name: "Amazon RDS MySQL",
        explanation: "RDS (Relational Database Service) menyediakan MySQL yang dikelola AWS: patching otomatis, backup otomatis, Multi-AZ failover. Buat DB instance, pilih instance class, dan konfigurasi parameter group.",
        ytKeyword: "AWS RDS MySQL tutorial setup",
        docUrl: "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_MySQL.html"
      },
      {
        name: "Menempatkan RDS di Private Subnet",
        explanation: "RDS seharusnya tidak bisa diakses langsung dari internet. Tempatkan di private subnet dan buat DB Subnet Group yang mencakup minimal 2 AZ. Hanya EC2 di VPC yang sama yang bisa connect.",
        ytKeyword: "AWS RDS private subnet VPC database security",
        docUrl: ""
      },
      {
        name: "Koneksi Aplikasi ke Database RDS",
        explanation: "Dapatkan endpoint RDS dari console. Di Laravel, konfigurasikan DB_HOST, DB_PORT=3306, DB_DATABASE, DB_USERNAME, DB_PASSWORD di file .env. Pastikan security group RDS mengizinkan koneksi dari EC2.",
        ytKeyword: "Laravel koneksi RDS MySQL AWS EC2",
        docUrl: ""
      },
      {
        name: "Amazon FSx sebagai File Storage",
        explanation: "FSx menyediakan sistem file terkelola: FSx for Windows File Server (SMB) atau FSx for Lustre (HPC). Berguna untuk shared storage antar instance, menggantikan file server on-premise.",
        ytKeyword: "AWS FSx file storage tutorial",
        docUrl: "https://docs.aws.amazon.com/fsx/latest/WindowsGuide/what-is.html"
      },
      {
        name: "Strategi Backup dan Recovery",
        explanation: "Terapkan aturan 3-2-1: 3 copy data, 2 media berbeda, 1 offsite (cross-region S3). Dokumentasikan RTO (Recovery Time Objective) dan RPO (Recovery Point Objective) proyek.",
        ytKeyword: "backup recovery strategy AWS RTO RPO",
        docUrl: ""
      },
      {
        name: "Pengujian Koneksi Database",
        explanation: "Dari EC2, uji koneksi ke RDS dengan: mysql -h <endpoint> -u <user> -p. Pastikan latency rendah (dalam AZ yang sama). Test query CRUD dasar untuk validasi konfigurasi.",
        ytKeyword: "test koneksi MySQL RDS EC2 AWS",
        docUrl: ""
      }
    ]
  },
  {
    id: 5,
    title: "Deployment Aplikasi Web",
    badge: "Deployment",
    badgeClass: "badge-deployment",
    description: "Deploy aplikasi Laravel/CakePHP ke EC2, konfigurasi web server, dan optionally gunakan Docker atau Elastic Beanstalk.",
    topics: [
      {
        name: "Persiapan Aplikasi Laravel / CakePHP",
        explanation: "Pastikan aplikasi berjalan di local terlebih dahulu. Verifikasi struktur project, file composer.json, .env.example, dan semua dependency sudah terdefinisi dengan benar.",
        ytKeyword: "persiapan deploy Laravel CakePHP AWS",
        docUrl: "https://laravel.com/docs"
      },
      {
        name: "Composer Install",
        explanation: "Composer adalah package manager PHP. Install di EC2: curl -sS https://getcomposer.org/installer | php && sudo mv composer.phar /usr/local/bin/composer. Jalankan composer install di folder project.",
        ytKeyword: "install Composer PHP di Linux EC2 AWS",
        docUrl: "https://getcomposer.org/doc/00-intro.md"
      },
      {
        name: "Konfigurasi File Environment (.env)",
        explanation: "Copy .env.example menjadi .env. Isi APP_KEY (php artisan key:generate), DB_HOST (RDS endpoint), DB_DATABASE, DB_USERNAME, DB_PASSWORD, dan konfigurasi storage.",
        ytKeyword: "konfigurasi .env Laravel EC2 production",
        docUrl: ""
      },
      {
        name: "Clone Project dari GitHub ke EC2",
        explanation: "Di EC2: git clone https://github.com/user/repo.git /var/www/html/myapp. Gunakan deploy key atau HTTPS token untuk autentikasi. Setup git hooks untuk otomasi deploy.",
        ytKeyword: "git clone project GitHub ke EC2 AWS deploy",
        docUrl: ""
      },
      {
        name: "Setup Apache/Nginx Virtual Host",
        explanation: "Buat konfigurasi virtual host yang mengarahkan domain ke folder public/ Laravel. Aktifkan mod_rewrite (Apache) atau konfigurasi try_files (Nginx) agar routing framework berfungsi.",
        ytKeyword: "Apache Nginx virtual host Laravel setup EC2",
        docUrl: ""
      },
      {
        name: "Permission Folder Aplikasi",
        explanation: "Folder storage/ dan bootstrap/cache/ harus writable oleh web server: sudo chown -R www-data:www-data storage bootstrap/cache && sudo chmod -R 755 storage bootstrap/cache.",
        ytKeyword: "Laravel permission folder storage EC2 Linux",
        docUrl: ""
      },
      {
        name: "Migrasi Database MySQL",
        explanation: "Jalankan php artisan migrate untuk membuat tabel dari migration files. Gunakan php artisan db:seed untuk data awal. Pastikan koneksi ke RDS sudah benar sebelum menjalankan migrasi.",
        ytKeyword: "Laravel migrate database RDS AWS artisan",
        docUrl: ""
      },
      {
        name: "Deployment menggunakan Git",
        explanation: "Workflow: git pull origin main di EC2 → composer install → php artisan migrate → php artisan config:cache → php artisan route:cache → restart web server.",
        ytKeyword: "deploy Laravel Git workflow EC2 AWS production",
        docUrl: ""
      },
      {
        name: "Deployment menggunakan Docker Dasar",
        explanation: "Buat Dockerfile untuk aplikasi PHP, docker-compose.yml untuk multi-service (app + nginx + db). Build image, push ke ECR, dan run container di EC2. Isolasi dependency antar proyek.",
        ytKeyword: "Docker deploy Laravel PHP tutorial dasar",
        docUrl: "https://docs.docker.com/get-started/"
      },
      {
        name: "Elastic Beanstalk (Alternatif)",
        explanation: "Elastic Beanstalk adalah PaaS AWS yang otomatis mengelola EC2, Load Balancer, Auto Scaling, dan deployment. Upload ZIP project atau gunakan EB CLI untuk deploy lebih mudah.",
        ytKeyword: "AWS Elastic Beanstalk deploy PHP Laravel tutorial",
        docUrl: "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/Welcome.html"
      },
      {
        name: "AWS Lightsail (Alternatif)",
        explanation: "Lightsail menawarkan VPS dengan harga tetap yang lebih sederhana dari EC2. Cocok untuk proyek kecil-menengah. Include blueprint Laravel siap pakai.",
        ytKeyword: "AWS Lightsail tutorial deploy website",
        docUrl: "https://aws.amazon.com/lightsail/"
      },
      {
        name: "AWS Lambda untuk Serverless",
        explanation: "Lambda menjalankan fungsi tanpa mengelola server. Bayar per eksekusi. Cocok untuk API endpoint ringan, image processing, scheduled jobs. Integrasikan dengan API Gateway.",
        ytKeyword: "AWS Lambda serverless tutorial bahasa Indonesia",
        docUrl: "https://docs.aws.amazon.com/lambda/latest/dg/welcome.html"
      },
      {
        name: "Pengujian Fungsionalitas Aplikasi",
        explanation: "Test semua fitur utama: login/logout, CRUD data, upload file ke S3, koneksi database. Gunakan browser, Postman untuk API, dan curl untuk scripted testing.",
        ytKeyword: "pengujian fungsionalitas aplikasi web deploy",
        docUrl: ""
      }
    ]
  },
  {
    id: 6,
    title: "Skalabilitas & High Availability",
    badge: "Scaling",
    badgeClass: "badge-scaling",
    description: "Implementasikan Load Balancer, Auto Scaling Group, dan caching untuk sistem yang tahan beban tinggi dan selalu tersedia.",
    topics: [
      {
        name: "Application Load Balancer (ALB)",
        explanation: "ALB mendistribusikan traffic HTTP/HTTPS ke beberapa EC2 instance secara otomatis. Dukung path-based dan host-based routing. Bisa terminate SSL dan integrasi dengan ACM.",
        ytKeyword: "AWS Application Load Balancer ALB tutorial",
        docUrl: "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/introduction.html"
      },
      {
        name: "Target Group",
        explanation: "Target Group adalah kumpulan instance (EC2, Lambda, IP) yang menerima traffic dari Load Balancer. Definisikan health check path (misal: /health) untuk menentukan instance yang sehat.",
        ytKeyword: "AWS target group load balancer tutorial",
        docUrl: ""
      },
      {
        name: "Auto Scaling Group (ASG)",
        explanation: "ASG otomatis menambah/mengurangi jumlah EC2 instance berdasarkan beban. Tentukan min, max, dan desired capacity. Gunakan bersama Launch Template dan Load Balancer.",
        ytKeyword: "AWS Auto Scaling Group tutorial setup",
        docUrl: "https://docs.aws.amazon.com/autoscaling/ec2/userguide/AutoScalingGroup.html"
      },
      {
        name: "Launch Template",
        explanation: "Launch Template menyimpan konfigurasi EC2 (AMI, instance type, security group, user data script) yang akan digunakan ASG saat membuat instance baru secara otomatis.",
        ytKeyword: "AWS Launch Template Auto Scaling tutorial",
        docUrl: ""
      },
      {
        name: "Konsep Multi-AZ",
        explanation: "Deploy instance di beberapa Availability Zone (minimal 2) dalam satu region. Jika satu AZ mengalami masalah, traffic otomatis dialihkan ke AZ lain. Wajib untuk High Availability.",
        ytKeyword: "AWS Multi AZ deployment high availability",
        docUrl: ""
      },
      {
        name: "Health Check",
        explanation: "Load Balancer secara berkala melakukan health check ke setiap instance. Jika instance gagal health check beberapa kali berturut-turut, traffic tidak akan diarahkan ke instance tersebut.",
        ytKeyword: "AWS load balancer health check configuration",
        docUrl: ""
      },
      {
        name: "Scaling Policy",
        explanation: "Definisikan kapan ASG scale-out (tambah instance) dan scale-in (kurangi instance). Gunakan Target Tracking Policy berdasarkan CPU utilization atau custom CloudWatch metric.",
        ytKeyword: "AWS Auto Scaling policy target tracking CPU",
        docUrl: "https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-target-tracking.html"
      },
      {
        name: "Redis untuk Caching",
        explanation: "Redis (via Amazon ElastiCache) menyimpan data session dan cache query di memori untuk akses super cepat. Di Laravel, ubah CACHE_DRIVER=redis dan SESSION_DRIVER=redis di .env.",
        ytKeyword: "AWS ElastiCache Redis Laravel caching tutorial",
        docUrl: "https://aws.amazon.com/elasticache/redis/"
      },
      {
        name: "Memcached untuk Caching",
        explanation: "Memcached adalah sistem caching in-memory sederhana. Cocok untuk caching objek sederhana. ElastiCache menyediakan Memcached terkelola. Lebih ringan dari Redis namun lebih terbatas fiturnya.",
        ytKeyword: "AWS ElastiCache Memcached tutorial",
        docUrl: ""
      },
      {
        name: "Pengujian Performa dengan Beban Berbeda",
        explanation: "Gunakan Apache Bench (ab) atau Locust untuk simulasi beban: ab -n 1000 -c 100 http://your-alb-url/. Pantau Auto Scaling bekerja saat CPU meningkat. Dokumentasikan hasil pengujian.",
        ytKeyword: "load testing AWS Auto Scaling Apache Bench Locust",
        docUrl: ""
      }
    ]
  },
  {
    id: 7,
    title: "Monitoring, Logging & Optimasi",
    badge: "Monitoring",
    badgeClass: "badge-monitoring",
    description: "Pantau kesehatan sistem dengan CloudWatch, analisis log, optimalkan biaya, dan tingkatkan performa aplikasi.",
    topics: [
      {
        name: "Amazon CloudWatch — Metrik Dasar",
        explanation: "CloudWatch mengumpulkan metrik dari semua layanan AWS. Pantau CPU Utilization, NetworkIn/Out, DiskReadOps, dan StatusCheckFailed EC2. Data tersedia dalam interval 1 atau 5 menit.",
        ytKeyword: "AWS CloudWatch monitoring metrics tutorial",
        docUrl: "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html"
      },
      {
        name: "Metrik CPU, Memory, Network, Disk",
        explanation: "CPU & Network tersedia default. Memory & Disk butuh CloudWatch Agent yang diinstall di EC2. Install agent: sudo yum install amazon-cloudwatch-agent, lalu konfigurasi dengan wizard.",
        ytKeyword: "CloudWatch agent memory disk metrics EC2 tutorial",
        docUrl: "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Install-CloudWatch-Agent.html"
      },
      {
        name: "Alarm CloudWatch",
        explanation: "Buat alarm yang triggered saat metrik melewati threshold. Misal: alarm jika CPU > 80% selama 5 menit, kirim notifikasi via SNS (email/SMS). Gunakan alarm untuk trigger Auto Scaling.",
        ytKeyword: "AWS CloudWatch alarm SNS notification setup",
        docUrl: ""
      },
      {
        name: "Log Aplikasi & Log Server",
        explanation: "Kirim log Nginx/Apache dan log Laravel ke CloudWatch Logs menggunakan CloudWatch Agent. Buat Log Group per aplikasi. Gunakan Log Insights untuk query log secara cepat.",
        ytKeyword: "CloudWatch Logs aplikasi server tutorial",
        docUrl: ""
      },
      {
        name: "AWS Athena untuk Analisis Log",
        explanation: "Athena adalah query engine serverless untuk menganalisis data di S3 menggunakan SQL standar. Gunakan untuk analisis access log ALB atau CloudFront log yang tersimpan di S3.",
        ytKeyword: "AWS Athena query S3 log analysis tutorial",
        docUrl: "https://docs.aws.amazon.com/athena/latest/ug/what-is.html"
      },
      {
        name: "Amazon Kinesis",
        explanation: "Kinesis memproses data streaming real-time dalam jumlah besar. Kinesis Data Streams untuk ingestion, Kinesis Data Firehose untuk deliver ke S3/Elasticsearch, Kinesis Analytics untuk real-time SQL.",
        ytKeyword: "AWS Kinesis streaming data tutorial",
        docUrl: "https://docs.aws.amazon.com/kinesis/latest/dev/introduction.html"
      },
      {
        name: "AWS Glue",
        explanation: "Glue adalah layanan ETL (Extract, Transform, Load) serverless. Crawl schema dari S3 atau database, transformasi data dengan PySpark, dan load ke data warehouse seperti Redshift.",
        ytKeyword: "AWS Glue ETL tutorial data pipeline",
        docUrl: "https://docs.aws.amazon.com/glue/latest/dg/what-is-glue.html"
      },
      {
        name: "AWS Budget & Optimasi Biaya",
        explanation: "Buat Budget Alert di AWS Billing agar mendapat notifikasi saat biaya mendekati limit. Gunakan Cost Explorer untuk analisis pola pengeluaran. Identifikasi resource yang tidak terpakai.",
        ytKeyword: "AWS Budget Cost Explorer optimasi biaya",
        docUrl: "https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html"
      },
      {
        name: "Optimasi Performa Aplikasi",
        explanation: "Teknik optimasi: enable OPcache PHP, minify CSS/JS, lazy load gambar, gunakan Redis untuk session/cache, optimalkan query database dengan EXPLAIN dan index, gunakan CDN untuk aset statis.",
        ytKeyword: "optimasi performa aplikasi PHP Laravel AWS",
        docUrl: ""
      },
      {
        name: "Analisis Bottleneck Aplikasi",
        explanation: "Identifikasi bottleneck: pantau slow query di RDS (Performance Insights), cek memory leak di aplikasi, analisis request yang lambat di CloudWatch Logs. Prioritaskan optimasi berdasarkan dampak.",
        ytKeyword: "analisis bottleneck aplikasi web performance profiling",
        docUrl: ""
      }
    ]
  },
  {
    id: 8,
    title: "Pengujian, Dokumentasi & Presentasi",
    badge: "Documentation",
    badgeClass: "badge-docs",
    description: "Validasi sistem secara menyeluruh, buat dokumentasi teknis & pengguna, dan siapkan presentasi proyek yang meyakinkan juri.",
    topics: [
      {
        name: "Pengujian Fungsionalitas Sistem",
        explanation: "Buat test case untuk setiap fitur utama. Uji happy path dan edge case. Dokumentasikan hasil testing dalam tabel: fitur, langkah uji, hasil yang diharapkan, hasil aktual, status (Pass/Fail).",
        ytKeyword: "functional testing web application checklist",
        docUrl: ""
      },
      {
        name: "Pengujian Keamanan Dasar",
        explanation: "Verifikasi: semua koneksi via HTTPS, tidak ada port yang terbuka tidak perlu, password default tidak digunakan, input validation mencegah SQL injection dan XSS, S3 tidak public tanpa sengaja.",
        ytKeyword: "web application security testing checklist OWASP",
        docUrl: ""
      },
      {
        name: "Pengujian Performa",
        explanation: "Gunakan ab (Apache Bench) untuk load test: ab -n 500 -c 50 https://domain.com/. Catat response time, requests/sec, dan error rate. Bandingkan sebelum dan sesudah optimasi.",
        ytKeyword: "performance testing web server Apache Bench tutorial",
        docUrl: ""
      },
      {
        name: "Dokumentasi Teknis",
        explanation: "Dokumentasi teknis mencakup: arsitektur sistem, spesifikasi layanan AWS yang digunakan, konfigurasi jaringan (IP, subnet, security group), prosedur deployment, dan troubleshooting guide.",
        ytKeyword: "dokumentasi teknis sistem cloud AWS template",
        docUrl: ""
      },
      {
        name: "Dokumentasi Pengguna",
        explanation: "Panduan pengguna yang mudah dipahami: cara login, cara menggunakan fitur utama, FAQ, dan cara menghubungi support. Gunakan screenshot dengan anotasi yang jelas.",
        ytKeyword: "membuat dokumentasi pengguna user manual",
        docUrl: ""
      },
      {
        name: "Screenshot Konfigurasi",
        explanation: "Dokumentasikan konfigurasi AWS dengan screenshot: VPC, subnet, security group, EC2, RDS, S3, IAM, CloudWatch. Beri caption yang jelas pada setiap screenshot.",
        ytKeyword: "dokumentasi screenshot konfigurasi AWS",
        docUrl: ""
      },
      {
        name: "Diagram Arsitektur Akhir",
        explanation: "Buat diagram arsitektur final menggunakan ikon resmi AWS di Draw.io. Tampilkan seluruh komponen, aliran data, zona keamanan (public/private), dan koneksi antar layanan.",
        ytKeyword: "AWS architecture diagram final draw.io tutorial",
        docUrl: "https://aws.amazon.com/architecture/icons/"
      },
      {
        name: "Checklist Validasi Proyek",
        explanation: "Buat checklist lengkap: ✓ HTTPS aktif, ✓ MFA enabled, ✓ Database di private subnet, ✓ Backup configured, ✓ Monitoring active, ✓ Auto Scaling configured, ✓ Dokumentasi lengkap.",
        ytKeyword: "AWS project validation checklist best practice",
        docUrl: ""
      },
      {
        name: "Penyusunan Presentasi Proyek",
        explanation: "Struktur presentasi: problem statement → solusi cloud → arsitektur → demo fitur → pengujian → biaya estimasi → inovasi → kesimpulan. Gunakan slide yang bersih dan informatif.",
        ytKeyword: "presentasi proyek cloud computing tips",
        docUrl: ""
      },
      {
        name: "Tips Menjelaskan Solusi Cloud kepada Juri",
        explanation: "Jelaskan mengapa setiap layanan dipilih (justifikasi teknis). Tunjukkan pemahaman trade-off (biaya vs performa). Siapkan jawaban untuk: kenapa tidak pakai X, bagaimana kalau traffic naik 10x.",
        ytKeyword: "tips presentasi proyek cloud computing AWS teknis",
        docUrl: ""
      }
    ]
  },
  {
    id: 9,
    title: "Inovasi & Kreativitas",
    badge: "Innovation",
    badgeClass: "badge-innovation",
    description: "Tambahkan nilai lebih pada proyek cloud kamu dengan inovasi AI/ML, layanan modern AWS, dan kreativitas dalam pemecahan masalah.",
    topics: [
      {
        name: "Amazon SageMaker — AI/ML",
        explanation: "SageMaker adalah platform AWS untuk build, train, dan deploy model machine learning. Bisa diintegrasikan dengan aplikasi web untuk fitur seperti sentiment analysis atau image recognition.",
        ytKeyword: "AWS SageMaker AI ML tutorial beginner",
        docUrl: "https://docs.aws.amazon.com/sagemaker/latest/dg/whatis.html"
      },
      {
        name: "AWS AppSync",
        explanation: "AppSync menyediakan GraphQL API yang terkelola. Mendukung real-time data dengan subscriptions dan offline sync untuk aplikasi mobile. Integrasikan dengan DynamoDB, Lambda, atau RDS.",
        ytKeyword: "AWS AppSync GraphQL API tutorial",
        docUrl: "https://docs.aws.amazon.com/appsync/latest/devguide/what-is-appsync.html"
      },
      {
        name: "AWS Amplify",
        explanation: "Amplify adalah framework fullstack untuk deploy aplikasi web dan mobile ke AWS. Mendukung CI/CD otomatis dari GitHub, hosting frontend, authentication, API, dan storage dalam satu CLI.",
        ytKeyword: "AWS Amplify tutorial fullstack deploy",
        docUrl: "https://docs.amplify.aws/"
      },
      {
        name: "Kinesis Video Stream",
        explanation: "Kinesis Video Streams memungkinkan streaming video secara real-time dari kamera/IoT ke AWS. Bisa diproses dengan Rekognition untuk analitik video (deteksi wajah, objek).",
        ytKeyword: "AWS Kinesis Video Streams IoT tutorial",
        docUrl: "https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/what-is-kinesis-video.html"
      },
      {
        name: "Ide Inovasi Sederhana untuk Proyek Cloud",
        explanation: "Contoh inovasi relevan: dashboard analitik real-time dengan Kinesis + QuickSight, chatbot customer service dengan Amazon Lex, notifikasi otomatis via SNS/SES, auto-tagging gambar dengan Rekognition.",
        ytKeyword: "ide inovasi cloud computing proyek AWS",
        docUrl: ""
      },
      {
        name: "Memilih Inovasi yang Relevan dengan Proyek",
        explanation: "Inovasi harus menyelesaikan masalah nyata dalam proyek, bukan sekadar menambah kompleksitas. Pastikan dapat didemonstrasikan dengan jelas, tidak merusak fitur utama, dan ada justifikasi bisnis.",
        ytKeyword: "memilih inovasi teknologi cloud yang tepat",
        docUrl: ""
      },
      {
        name: "Kreativitas dalam Menyelesaikan Masalah Cloud",
        explanation: "Berpikir kreatif: kombinasikan layanan AWS yang tidak biasa, optimasi arsitektur untuk use case spesifik, atau gunakan serverless untuk mengurangi biaya secara signifikan. Dokumentasikan proses berpikir.",
        ytKeyword: "cloud architecture creativity problem solving AWS",
        docUrl: ""
      }
    ]
  }
];

/* ============================================================
   2. UTILITY: Hitung total sub-materi
   ============================================================ */
function countTotalTopics() {
  return roadmap.reduce((sum, stage) => sum + stage.topics.length, 0);
}

/* ============================================================
   3. RENDER TIMELINE CARDS
   ============================================================ */
function renderTimeline() {
  const container = document.getElementById('timelineContainer');
  if (!container) return;

  container.innerHTML = '';

  roadmap.forEach((stage, index) => {
    const item = document.createElement('div');
    item.className = 'tl-item';
    item.setAttribute('data-index', index);

    item.innerHTML = `
      <!-- Card side -->
      <div class="tl-card-side">
        <div class="tl-card" role="button" tabindex="0" aria-label="Buka detail tahap ${stage.id}: ${stage.title}">
          <div class="card-top">
            <span class="card-stage-num">Tahap ${stage.id}</span>
            <span class="card-badge ${stage.badgeClass}">${stage.badge}</span>
          </div>
          <div class="card-title">${stage.title}</div>
          <div class="card-desc">${stage.description}</div>
          <div class="card-topic-count">${stage.topics.length} sub-materi</div>
          <div class="card-hint">→</div>
        </div>
      </div>

      <!-- Center dot -->
      <div class="tl-dot-side">
        <div class="tl-dot">${stage.id}</div>
      </div>

      <!-- Empty spacer for opposing side -->
      <div class="tl-card-side"></div>
    `;

    // Klik kartu atau dot → buka modal
    const card = item.querySelector('.tl-card');
    const dot  = item.querySelector('.tl-dot');

    card.addEventListener('click', () => openModal(index));
    dot.addEventListener('click',  () => openModal(index));

    // Keyboard accessibility
    card.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        openModal(index);
      }
    });

    container.appendChild(item);
  });

  // Update stat counter
  document.getElementById('totalTopic').textContent = countTotalTopics();

  // Jalankan Intersection Observer setelah render
  observeItems();
}

/* ============================================================
   4. INTERSECTION OBSERVER — Entrance animation
   ============================================================ */
function observeItems() {
  const items = document.querySelectorAll('.tl-item');
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        // Delay berdasarkan posisi agar efek stagger
        const delay = parseInt(entry.target.getAttribute('data-index')) % 3 * 80;
        setTimeout(() => {
          entry.target.classList.add('visible');
        }, delay);
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1 });

  items.forEach(item => observer.observe(item));
}

/* ============================================================
   5. MODAL — Open
   ============================================================ */
function openModal(stageIndex) {
  const stage = roadmap[stageIndex];
  if (!stage) return;

  const overlay   = document.getElementById('modalOverlay');
  const titleEl   = document.getElementById('modalTitle');
  const descEl    = document.getElementById('modalDesc');
  const badgeEl   = document.getElementById('modalStageBadge');
  const accordionList = document.getElementById('accordionList');

  // Isi header modal
  badgeEl.textContent  = `Tahap ${stage.id} — ${stage.badge}`;
  titleEl.textContent  = stage.title;
  descEl.textContent   = stage.description;

  // Kosongkan accordion lama
  accordionList.innerHTML = '';

  // Buat accordion untuk setiap sub-materi
  stage.topics.forEach((topic, i) => {
    const item = document.createElement('div');
    item.className = 'accordion-item';

    // Tombol YouTube
    const ytUrl = `https://www.youtube.com/results?search_query=${encodeURIComponent(topic.ytKeyword)}`;
    const ytBtn = `<a class="btn-yt" href="${ytUrl}" target="_blank" rel="noopener noreferrer">
      ▶ Cari di YouTube
    </a>`;

    // Tombol Dokumentasi (opsional)
    const docBtn = topic.docUrl
      ? `<a class="btn-doc" href="${topic.docUrl}" target="_blank" rel="noopener noreferrer">
          📄 Dokumentasi Resmi
        </a>`
      : '';

    item.innerHTML = `
      <button class="accordion-trigger" aria-expanded="false" aria-controls="acc-body-${stageIndex}-${i}">
        <span>${topic.name}</span>
        <span class="accordion-arrow">▾</span>
      </button>
      <div class="accordion-body" id="acc-body-${stageIndex}-${i}" role="region">
        <div class="accordion-content">
          <p>${topic.explanation}</p>
          <div class="accordion-actions">
            ${ytBtn}
            ${docBtn}
          </div>
        </div>
      </div>
    `;

    // Klik trigger → toggle accordion
    const trigger = item.querySelector('.accordion-trigger');
    trigger.addEventListener('click', () => toggleAccordion(item, accordionList));

    accordionList.appendChild(item);
  });

  // Tampilkan overlay
  overlay.classList.add('active');
  document.body.style.overflow = 'hidden'; // cegah scroll background

  // Fokus ke tombol close untuk aksesibilitas
  document.getElementById('modalClose').focus();
}

/* ============================================================
   6. ACCORDION — Toggle (hanya satu terbuka sekaligus)
   ============================================================ */
function toggleAccordion(clickedItem, listEl) {
  const isOpen = clickedItem.classList.contains('open');

  // Tutup semua accordion terlebih dahulu
  listEl.querySelectorAll('.accordion-item.open').forEach(openItem => {
    openItem.classList.remove('open');
    openItem.querySelector('.accordion-trigger').setAttribute('aria-expanded', 'false');
  });

  // Jika item yang diklik belum terbuka, buka sekarang
  if (!isOpen) {
    clickedItem.classList.add('open');
    clickedItem.querySelector('.accordion-trigger').setAttribute('aria-expanded', 'true');
  }
}

/* ============================================================
   7. MODAL — Close
   ============================================================ */
function closeModal() {
  const overlay = document.getElementById('modalOverlay');
  overlay.classList.remove('active');
  document.body.style.overflow = ''; // kembalikan scroll
}

/* ---- Tombol X ---- */
document.getElementById('modalClose').addEventListener('click', closeModal);

/* ---- Klik overlay di luar modal box ---- */
document.getElementById('modalOverlay').addEventListener('click', function(e) {
  if (e.target === this) closeModal();
});

/* ---- Tombol Escape ---- */
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') closeModal();
});

/* ============================================================
   8. INIT
   ============================================================ */
document.addEventListener('DOMContentLoaded', () => {
  renderTimeline();
});
