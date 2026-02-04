const Fastify = require("fastify");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const cors = require("@fastify/cors");
const jwt = require("jsonwebtoken");
const multipart = require("@fastify/multipart");
const { v4: uuidv4 } = require('uuid');
const nodemailer = require("nodemailer");

const app = Fastify({ logger: true });
const prisma = new PrismaClient();

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

// Email Transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// Helper: Send Email
const sendEmail = async (to, subject, html) => {
  try {
    await transporter.sendMail({
      from: `"Jesa World SMS" <${process.env.SMTP_USER}>`,
      to,
      subject,
      html,
    });
  } catch (error) {
    app.log.error("Failed to send email:", error);
  }
};

// Helper: Generate Unique School Number
const generateSchoolNumber = async () => {
  let unique = false;
  let number = "";
  while (!unique) {
    number = Math.floor(100000 + Math.random() * 900000).toString(); // 6 digit number
    const existing = await prisma.school.findUnique({ where: { schoolNumber: number } });
    if (!existing) unique = true;
  }
  return number;
};

async function start() {
  await app.register(cors, {
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  });

  await app.register(multipart, {
    limits: { fileSize: 5 * 1024 * 1024 },
  });

  // Middleware: Authenticate JWT
  app.decorate("authenticate", async (request, reply) => {
    try {
      const token = request.headers.authorization?.split(" ")[1];
      if (!token) throw new Error("No token provided");
      const decoded = jwt.verify(token, JWT_SECRET);
      request.user = decoded;
    } catch (err) {
      reply.code(401).send({ error: "Unauthorized" });
    }
  });

  // --- Auth Routes ---

  // Super Admin Registration
  app.post("/api/auth/superadmin/register", async (request, reply) => {
    const { email, password, firstName, lastName } = request.body;

    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();

      const user = await prisma.user.create({
        data: {
          email,
          password: hashedPassword,
          firstName,
          lastName,
          role: "SUPERADMIN",
          isEmailVerified: false,
          verificationCode
        }
      });

      // Send Verification Email
      await sendEmail(
        email,
        "Verify your Super Admin Account",
        `<p>Your verification code is: <strong>${verificationCode}</strong></p>`
      );

      return { message: "Verification code sent to email", email };
    } catch (err) {
      if (err.code === 'P2002') {
        return reply.code(400).send({ error: "Email already exists" });
      }
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to initiate super admin registration" });
    }
  });

  // Verify Email Endpoint
  app.post("/api/auth/superadmin/verify-email", async (request, reply) => {
    const { email, code } = request.body;

    try {
      const user = await prisma.user.findUnique({ where: { email } });

      if (!user || user.verificationCode !== code) {
        return reply.code(400).send({ error: "Invalid verification code" });
      }

      await prisma.user.update({
        where: { email },
        data: {
          isEmailVerified: true,
          verificationCode: null
        }
      });

      const token = jwt.sign({ id: user.id, email: user.email, role: "SUPERADMIN" }, JWT_SECRET);
      return { token, user: { id: user.id, firstName: user.firstName, lastName: user.lastName, role: "SUPERADMIN" } };
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Verification failed" });
    }
  });

  // Login (Multi-tenant)
  app.post("/api/auth/login", async (request, reply) => {
    const { email, password, schoolNumber, role, studentId } = request.body;

    if (role === "SUPERADMIN") {
      const user = await prisma.user.findFirst({
        where: { email, role: "SUPERADMIN" }
      });
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return reply.code(401).send({ error: "Invalid credentials" });
      }

      if (!user.isEmailVerified) {
        return reply.code(403).send({ error: "Email not verified", requiresVerification: true });
      }

      // Generate 2FA Code
      const twoFactorCode = Math.floor(100000 + Math.random() * 900000).toString();
      const twoFactorExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

      await prisma.user.update({
        where: { id: user.id },
        data: { twoFactorCode, twoFactorExpires }
      });

      // Send 2FA Email
      await sendEmail(
        email,
        "Your 2FA Login Code",
        `<p>Your login code is: <strong>${twoFactorCode}</strong>. Use this to complete your login.</p>`
      );

      return { requires2FA: true, email };
    }

    // Student Login: Use studentId + password
    if (role === "STUDENT") {
      if (!studentId) return reply.code(400).send({ error: "Student ID is required" });

      const user = await prisma.user.findFirst({
        where: {
          studentId,
          role: "STUDENT"
        },
        include: { school: true }
      });

      if (!user || !user.isActive || !(await bcrypt.compare(password, user.password))) {
        return reply.code(401).send({ error: "Invalid credentials or account inactive" });
      }

      // Check School Validity
      const now = new Date();
      const validUntil = new Date(user.school.validUntil);
      if (now > validUntil) {
        return reply.code(403).send({
          error: "School license expired. Please contact Super Admin.",
          isSchoolExpired: true,
          validUntil: user.school.validUntil
        });
      }

      const token = jwt.sign({
        id: user.id,
        email: user.email,
        role: user.role,
        schoolId: user.schoolId,
        schoolNumber: user.school.schoolNumber
      }, JWT_SECRET);

      return {
        token,
        user: {
          id: user.id,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          schoolName: user.school.name,
          studentId: user.studentId
        }
      };
    }

    // Teacher Login: Use email + password (no school number)
    if (role === "TEACHER") {
      if (!email) return reply.code(400).send({ error: "Email is required" });

      const user = await prisma.user.findFirst({
        where: {
          email,
          role: "TEACHER"
        },
        include: { school: true }
      });

      if (!user || !user.isActive || !(await bcrypt.compare(password, user.password))) {
        return reply.code(401).send({ error: "Invalid credentials or account inactive" });
      }

      // Check School Validity
      const now = new Date();
      const validUntil = new Date(user.school.validUntil);
      if (now > validUntil) {
        return reply.code(403).send({
          error: "School license expired. Please contact Super Admin.",
          isSchoolExpired: true,
          validUntil: user.school.validUntil
        });
      }

      const token = jwt.sign({
        id: user.id,
        email: user.email,
        role: user.role,
        schoolId: user.schoolId,
        schoolNumber: user.school.schoolNumber
      }, JWT_SECRET);

      return {
        token,
        user: {
          id: user.id,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          schoolName: user.school.name
        }
      };
    }

    // Admin Login: Use schoolNumber + email + password
    if (role === "ADMIN") {
      if (!schoolNumber) return reply.code(400).send({ error: "School number is required" });
      if (!email) return reply.code(400).send({ error: "Email is required" });

      const user = await prisma.user.findFirst({
        where: {
          email,
          role: "ADMIN",
          school: { schoolNumber }
        },
        include: { school: true }
      });

      if (!user || !user.isActive || !(await bcrypt.compare(password, user.password))) {
        return reply.code(401).send({ error: "Invalid credentials or account inactive" });
      }

      // Check School Validity
      const now = new Date();
      const validUntil = new Date(user.school.validUntil);
      if (now > validUntil) {
        return reply.code(403).send({
          error: "School license expired. Please contact Super Admin.",
          isSchoolExpired: true,
          validUntil: user.school.validUntil
        });
      }

      const token = jwt.sign({
        id: user.id,
        email: user.email,
        role: user.role,
        schoolId: user.schoolId,
        schoolNumber: user.school.schoolNumber
      }, JWT_SECRET);

      return {
        token,
        user: {
          id: user.id,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          schoolName: user.school.name
        }
      };
    }

    return reply.code(400).send({ error: "Invalid role specified" });
  });

  // Verify 2FA Endpoint
  app.post("/api/auth/superadmin/verify-2fa", async (request, reply) => {
    const { email, code } = request.body;

    try {
      const user = await prisma.user.findFirst({
        where: { email, role: "SUPERADMIN" }
      });

      if (!user || user.twoFactorCode !== code || new Date() > new Date(user.twoFactorExpires)) {
        return reply.code(400).send({ error: "Invalid or expired 2FA code" });
      }

      // Clear code
      await prisma.user.update({
        where: { id: user.id },
        data: { twoFactorCode: null, twoFactorExpires: null }
      });

      const token = jwt.sign({ id: user.id, email: user.email, role: "SUPERADMIN" }, JWT_SECRET);
      return { token, user: { id: user.id, firstName: user.firstName, lastName: user.lastName, role: "SUPERADMIN" } };
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "2FA verification failed" });
    }
  });

  // --- Super Admin Routes ---

  // Create School
  app.post("/api/superadmin/schools", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "SUPERADMIN") return reply.code(403).send({ error: "Forbidden" });

    const { name, address, phone, email, maxStudents, maxTeachers, adminEmail, adminPassword, adminFirstName, adminLastName } = request.body;

    try {
      const schoolNumber = await generateSchoolNumber();
      const hashedPassword = await bcrypt.hash(adminPassword, 10);

      // Calculate validUntil (4 months from now)
      // Note: DB also handles default, but explicit setting ensures consistency in application logic if needed
      // We will rely on DB default or set it here if we want to be explicit. 
      // Using DB default as defined in schema: @default(dbgenerated("NOW() + interval '4 months'"))
      // So no need to pass validUntil unless we want to override.

      const school = await prisma.school.create({
        data: {
          name,
          address,
          phone,
          email,
          schoolNumber,
          maxStudents: parseInt(maxStudents) || 100,
          maxTeachers: parseInt(maxTeachers) || 10,
          users: {
            create: {
              email: adminEmail,
              password: hashedPassword,
              firstName: adminFirstName,
              lastName: adminLastName,
              role: "ADMIN"
            }
          }
        },
        include: { users: true }
      });

      return school;
    } catch (err) {
      if (err.code === 'P2002') {
        return reply.code(400).send({ error: "Email or School Number already exists" });
      }
      app.log.error(err);
      return reply.code(500).send({ error: "Internal server error during school creation" });
    }
  });

  // List All Administrators (Global)
  app.get("/api/superadmin/admins", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "SUPERADMIN") return reply.code(403).send({ error: "Forbidden" });

    try {
      const admins = await prisma.user.findMany({
        where: { role: "ADMIN" },
        include: { school: true },
        orderBy: { createdAt: 'desc' }
      });
      return admins;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to fetch administrators" });
    }
  });

  // Update Student/Teacher
  app.put("/api/admin/users/:id", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN" && request.user.role !== "SUPERADMIN") {
      return reply.code(403).send({ error: "Forbidden" });
    }

    const { id } = request.params;
    const { firstName, lastName, phone, address, studentClass, subjects } = request.body;
    const schoolId = request.user.role === "SUPERADMIN" ? request.body.schoolId : request.user.schoolId;

    try {
      // Ensure user belongs to the same school (if ADMIN)
      const existingUser = await prisma.user.findUnique({ where: { id } });

      if (!existingUser) return reply.code(404).send({ error: "User not found" });
      if (request.user.role === "ADMIN" && existingUser.schoolId !== schoolId) {
        return reply.code(403).send({ error: "Forbidden: User belongs to another school" });
      }

      const updatedUser = await prisma.user.update({
        where: { id },
        data: {
          firstName,
          lastName,
          phone,
          address,
          studentClass,
          subjects
        }
      });

      return updatedUser;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to update user" });
    }
  });

  // Get Super Admin Profile
  app.get("/api/superadmin/profile", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "SUPERADMIN") return reply.code(403).send({ error: "Forbidden" });
    try {
      const user = await prisma.user.findUnique({
        where: { id: request.user.id },
        select: { id: true, email: true, firstName: true, lastName: true, role: true, createdAt: true }
      });
      return user;
    } catch (err) {
      return reply.code(500).send({ error: "Failed to fetch profile" });
    }
  });

  // Update Super Admin Profile
  app.put("/api/superadmin/profile", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "SUPERADMIN") return reply.code(403).send({ error: "Forbidden" });
    const { firstName, lastName, email } = request.body;
    try {
      const user = await prisma.user.update({
        where: { id: request.user.id },
        data: { firstName, lastName, email }
      });
      return { message: "Profile updated successfully", user: { firstName: user.firstName, lastName: user.lastName, email: user.email } };
    } catch (err) {
      return reply.code(500).send({ error: "Failed to update profile" });
    }
  });

  // Change Password
  app.post("/api/superadmin/change-password", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "SUPERADMIN") return reply.code(403).send({ error: "Forbidden" });
    const { currentPassword, newPassword } = request.body;
    try {
      const user = await prisma.user.findUnique({ where: { id: request.user.id } });
      if (!user || !(await bcrypt.compare(currentPassword, user.password))) {
        return reply.code(400).send({ error: "Incorrect current password" });
      }
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await prisma.user.update({
        where: { id: request.user.id },
        data: { password: hashedPassword }
      });
      return { message: "Password updated successfully" };
    } catch (err) {
      return reply.code(500).send({ error: "Failed to change password" });
    }
  });

  // Reactivate School
  app.post("/api/superadmin/schools/:id/reactivate", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "SUPERADMIN") return reply.code(403).send({ error: "Forbidden" });
    const { id } = request.params;

    try {
      const school = await prisma.school.findUnique({ where: { id } });
      if (!school) return reply.code(404).send({ error: "School not found" });

      // Extend validity by 4 months from NOW
      const now = new Date();
      const validUntil = new Date(now.setMonth(now.getMonth() + 4));

      const updatedSchool = await prisma.school.update({
        where: { id },
        data: {
          validUntil,
          lastReactivatedAt: new Date()
        }
      });

      return {
        message: "School reactivated successfully",
        school: updatedSchool
      };
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to reactivate school" });
    }
  });

  // Delete School
  app.delete("/api/superadmin/schools/:id", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "SUPERADMIN") return reply.code(403).send({ error: "Forbidden" });
    const { id } = request.params;
    try {
      await prisma.school.delete({ where: { id } });
      return { message: "School deleted successfully" };
    } catch (err) {
      return reply.code(500).send({ error: "Failed to delete school" });
    }
  });

  // List Schools
  app.get("/api/superadmin/schools", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "SUPERADMIN") return reply.code(403).send({ error: "Forbidden" });

    const schools = await prisma.school.findMany({
      include: { _count: { select: { users: true } } }
    });

    // We can compute status here or in frontend. 
    // Frontend is better for display logic (e.g. expiring soon warning relative to client time), 
    // but we have validUntil in the data now.

    return schools;
  });

  // --- School Admin Routes ---

  // Add User (Admin/Teacher/Student)
  app.post("/api/admin/users", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN" && request.user.role !== "SUPERADMIN") {
      return reply.code(403).send({ error: "Forbidden" });
    }

    const { email, password, firstName, lastName, role, phone, address, schoolId: targetSchoolId, studentClass, subjects } = request.body;
    const schoolId = request.user.role === "SUPERADMIN" ? targetSchoolId : request.user.schoolId;

    if (!schoolId) return reply.code(400).send({ error: "School ID is required" });

    // Check Quotas
    const school = await prisma.school.findUnique({
      where: { id: schoolId },
      include: { _count: { select: { users: { where: { role } } } } }
    });

    if (role === "TEACHER" && school._count.users >= school.maxTeachers) {
      return reply.code(400).send({ error: "Teacher limit reached" });
    }
    if (role === "STUDENT" && school._count.users >= school.maxStudents) {
      return reply.code(400).send({ error: "Student limit reached" });
    }
    // Admins don't have a specific quota check here currently, 
    // but they are assigned to the school.

    // Generate student ID for students
    // Generate student ID for students
    let studentId = null;
    if (role === "STUDENT") {
      let unique = false;
      while (!unique) {
        const randomDigits = Math.floor(1000 + Math.random() * 9000).toString(); // 4 random digits
        studentId = `${school.schoolNumber}${randomDigits}`;

        const existing = await prisma.user.findUnique({ where: { studentId } });
        if (!existing) unique = true;
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        firstName,
        lastName,
        role,
        phone,
        address,
        school: { connect: { id: schoolId } },
        studentId,
        studentClass,
        subjects
      }
    });

    return user;
  });

  // Bulk Add Students (CSV Upload)
  app.post("/api/admin/users/bulk", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN" && request.user.role !== "SUPERADMIN") {
      return reply.code(403).send({ error: "Forbidden" });
    }

    const { students, schoolId: targetSchoolId } = request.body; // students is array of objects
    const schoolId = request.user.role === "SUPERADMIN" ? targetSchoolId : request.user.schoolId;

    if (!schoolId) return reply.code(400).send({ error: "School ID is required" });
    if (!students || !Array.isArray(students) || students.length === 0) {
      return reply.code(400).send({ error: "No students provided" });
    }

    // Check Quota
    const school = await prisma.school.findUnique({
      where: { id: schoolId },
      include: { _count: { select: { users: { where: { role: "STUDENT" } } } } }
    });

    if (school._count.users + students.length > school.maxStudents) {
      return reply.code(400).send({ error: `Cannot add ${students.length} students. Limit reached. Remaining slots: ${school.maxStudents - school._count.users}` });
    }

    const createdStudents = [];
    const errors = [];

    for (const student of students) {
      try {
        const { email, password, firstName, lastName, studentClass, phone, address, gender } = student;

        if (!email || !password || !firstName || !lastName || !studentClass) {
          errors.push({ email, error: "Missing required fields" });
          continue;
        }

        // Generate ID
        let unique = false;
        let studentId = "";
        while (!unique) {
          const randomDigits = Math.floor(1000 + Math.random() * 9000).toString();
          studentId = `${school.schoolNumber}${randomDigits}`;
          const existing = await prisma.user.findUnique({ where: { studentId } });
          if (!existing) unique = true;
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await prisma.user.create({
          data: {
            email,
            password: hashedPassword,
            firstName,
            lastName,
            role: "STUDENT",
            studentClass,
            studentId,
            schoolId,
            phone,
            address,
            // gender - if we add gender to schema later
          }
        });

        createdStudents.push({ email, studentId });
      } catch (err) {
        if (err.code === 'P2002') {
          errors.push({ email: student.email, error: "Email already exists" });
        } else {
          errors.push({ email: student.email, error: "Failed to create" });
          app.log.error(err);
        }
      }
    }

    return {
      message: `Processed ${students.length} students`,
      successCount: createdStudents.length,
      failureCount: errors.length,
      created: createdStudents,
      errors
    };
  });

  // Get Stats
  app.get("/api/admin/stats", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN") return reply.code(403).send({ error: "Forbidden" });
    const schoolId = request.user.schoolId;

    const teacherCount = await prisma.user.count({ where: { schoolId, role: "TEACHER" } });
    const studentCount = await prisma.user.count({ where: { schoolId, role: "STUDENT" } });

    return { teacherCount, studentCount };
  });

  // List Users by Role
  app.get("/api/admin/users/:role", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN" && request.user.role !== "SUPERADMIN") {
      return reply.code(403).send({ error: "Forbidden" });
    }
    const { role } = request.params;
    const { schoolId: querySchoolId } = request.query;
    const schoolId = request.user.role === "SUPERADMIN" ? querySchoolId : request.user.schoolId;

    if (!schoolId) return reply.code(400).send({ error: "School ID is required" });

    if (!["ADMIN", "TEACHER", "STUDENT"].includes(role)) {
      return reply.code(400).send({ error: "Invalid role" });
    }

    const users = await prisma.user.findMany({
      where: { schoolId, role },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        phone: true,
        address: true,
        isActive: true,
        createdAt: true,
        studentId: true,
        studentClass: true,
        subjects: true
      }
    });

    return users;
  });

  // Get Subjects
  app.get("/api/admin/subjects", { preHandler: [app.authenticate] }, async (request, reply) => {
    // Authenticate but allow any role with access to this data (probably Teacher/Admin/SuperAdmin)
    // Actually, Student probably doesn't need this full list unless they are choosing electives.
    // Spec says "Admin should be able to see...", so Admin/Teacher context usually.
    // I'll allow all authenticated for now as it's just a reference list.

    const subjects = await prisma.subject.findMany({
      orderBy: [
        { section: 'asc' },
        { category: 'asc' },
        { name: 'asc' }
      ]
    });
    return subjects;
  });

  // Add Subject
  app.post("/api/admin/subjects", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== 'ADMIN' && request.user.role !== 'SUPERADMIN') {
      return reply.code(403).send({ error: "Access denied" });
    }

    const { name, section, category } = request.body;

    if (!name || !section) {
      return reply.code(400).send({ error: "Name and Section are required" });
    }

    try {
      const subject = await prisma.subject.create({
        data: {
          name,
          section: section.toUpperCase(),
          category: category || "General"
        }
      });
      return subject;
    } catch (err) {
      if (err.code === 'P2002') {
        return reply.code(400).send({ error: "Subject name already exists" });
      }
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to create subject" });
    }
  });

  // Delete Subject
  app.delete("/api/admin/subjects/:id", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== 'ADMIN' && request.user.role !== 'SUPERADMIN') {
      return reply.code(403).send({ error: "Access denied" });
    }

    const { id } = request.params;

    try {
      await prisma.subject.delete({
        where: { id }
      });
      return { success: true };
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to delete subject" });
    }
  });

  // --- Exam Schedule Routes ---

  // List Exam Schedules
  app.get("/api/admin/exams", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN" && request.user.role !== "SUPERADMIN") {
      return reply.code(403).send({ error: "Forbidden" });
    }
    const schoolId = request.user.schoolId;

    try {
      const exams = await prisma.examSchedule.findMany({
        where: { schoolId },
        orderBy: { date: 'asc' }
      });
      return exams;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to fetch exam schedules" });
    }
  });

  // Create Exam Schedule
  app.post("/api/admin/exams", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN" && request.user.role !== "SUPERADMIN") {
      return reply.code(403).send({ error: "Forbidden" });
    }
    const schoolId = request.user.schoolId;
    const { subject, class: studentClass, date, time, duration, type } = request.body;

    try {
      const exam = await prisma.examSchedule.create({
        data: {
          subject,
          class: studentClass,
          date,
          time,
          duration,
          type,
          schoolId
        }
      });
      return exam;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to create exam schedule", details: err.message });
    }
  });

  // Update Exam Schedule
  app.put("/api/admin/exams/:id", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN" && request.user.role !== "SUPERADMIN") {
      return reply.code(403).send({ error: "Forbidden" });
    }
    const { id } = request.params;
    const schoolId = request.user.schoolId;
    const { subject, class: studentClass, date, time, duration, type } = request.body;

    try {
      const existingExam = await prisma.examSchedule.findUnique({ where: { id } });
      if (!existingExam || existingExam.schoolId !== schoolId) {
        return reply.code(404).send({ error: "Exam schedule not found" });
      }

      const updatedExam = await prisma.examSchedule.update({
        where: { id },
        data: {
          subject,
          class: studentClass,
          date,
          time,
          duration,
          type
        }
      });
      return updatedExam;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to update exam schedule" });
    }
  });

  // Delete Exam Schedule
  app.delete("/api/admin/exams/:id", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN" && request.user.role !== "SUPERADMIN") {
      return reply.code(403).send({ error: "Forbidden" });
    }
    const { id } = request.params;
    const schoolId = request.user.schoolId;

    try {
      const existingExam = await prisma.examSchedule.findUnique({ where: { id } });
      if (!existingExam || existingExam.schoolId !== schoolId) {
        return reply.code(404).send({ error: "Exam schedule not found" });
      }

      await prisma.examSchedule.delete({ where: { id } });
      return { success: true };
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to delete exam schedule" });
    }
  });

  // --- Student/Parent Routes ---

  // Get Student Profile (for parents)
  app.get("/api/student/profile", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "STUDENT") {
      return reply.code(403).send({ error: "Forbidden" });
    }

    try {
      const student = await prisma.user.findUnique({
        where: { id: request.user.id },
        include: { school: true },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          phone: true,
          address: true,
          createdAt: true,
          school: {
            select: {
              name: true,
              schoolNumber: true
            }
          }
        }
      });

      return student;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to fetch student profile" });
    }
  });

  // Get Student Results (placeholder for future grading system)
  app.get("/api/student/results", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "STUDENT") {
      return reply.code(403).send({ error: "Forbidden" });
    }

    // Placeholder - will be implemented when grading system is added
    return {
      message: "Results feature coming soon",
      results: []
    };
  });

  // Get Student Attendance (placeholder for future attendance system)
  app.get("/api/student/attendance", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "STUDENT") {
      return reply.code(403).send({ error: "Forbidden" });
    }

    // Placeholder - will be implemented when attendance system is added
    return {
      message: "Attendance feature coming soon",
      attendance: []
    };
  });

  // Root route
  app.get("/", async () => {
    return { message: "Jesa World SMS API is running!" };
  });

  try {
    const port = process.env.PORT || 4000;
    await app.listen({ port: Number(port), host: "0.0.0.0" });
    app.log.info(`🚀 Server listening on http://localhost:${port}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

start();