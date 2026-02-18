const Fastify = require("fastify");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const cors = require("@fastify/cors");
const jwt = require("jsonwebtoken");
const multipart = require("@fastify/multipart");
const { v4: uuidv4 } = require('uuid');
const nodemailer = require("nodemailer");
const mammoth = require("mammoth");
const { GoogleGenerativeAI } = require("@google/generative-ai");

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

  // Get Enrollment Trend
  app.get("/api/admin/enrollment-trend", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN") return reply.code(403).send({ error: "Forbidden" });
    const schoolId = request.user.schoolId;

    try {
      // Get all students for this school
      const students = await prisma.user.findMany({
        where: { schoolId, role: "STUDENT" },
        select: { createdAt: true }
      });

      // Group by month for the last 12 months
      const now = new Date();
      const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      const enrollmentData = [];

      for (let i = 11; i >= 0; i--) {
        const targetDate = new Date(now.getFullYear(), now.getMonth() - i, 1);
        const monthStart = new Date(targetDate.getFullYear(), targetDate.getMonth(), 1);
        const monthEnd = new Date(targetDate.getFullYear(), targetDate.getMonth() + 1, 0, 23, 59, 59);

        const count = students.filter(s => {
          const createdDate = new Date(s.createdAt);
          return createdDate >= monthStart && createdDate <= monthEnd;
        }).length;

        enrollmentData.push({
          month: monthNames[targetDate.getMonth()],
          count
        });
      }

      return { enrollmentData };
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to fetch enrollment trend" });
    }
  });

  // Bulk Promote/Demote Students
  app.post("/api/admin/users/bulk-promote", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN" && request.user.role !== "SUPERADMIN") {
      return reply.code(403).send({ error: "Forbidden" });
    }

    const { studentIds, newClass } = request.body;
    const schoolId = request.user.schoolId;

    if (!studentIds || !Array.isArray(studentIds) || studentIds.length === 0) {
      return reply.code(400).send({ error: "Student IDs array is required" });
    }

    if (!newClass) {
      return reply.code(400).send({ error: "New class is required" });
    }

    try {
      // Verify all students belong to this school
      const students = await prisma.user.findMany({
        where: {
          id: { in: studentIds },
          schoolId,
          role: "STUDENT"
        }
      });

      if (students.length !== studentIds.length) {
        return reply.code(400).send({ error: "Some students not found or don't belong to your school" });
      }

      // Update all students
      const result = await prisma.user.updateMany({
        where: {
          id: { in: studentIds },
          schoolId
        },
        data: {
          studentClass: newClass
        }
      });

      return {
        message: `Successfully updated ${result.count} students to ${newClass}`,
        count: result.count
      };
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to bulk promote students" });
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

  // --- Grading System Routes ---

  // List Grading Rules
  app.get("/api/admin/grading", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN" && request.user.role !== "SUPERADMIN") {
      return reply.code(403).send({ error: "Forbidden" });
    }
    const schoolId = request.user.schoolId;

    try {
      const grading = await prisma.gradingSystem.findMany({
        where: { schoolId },
        orderBy: { minScore: 'desc' }
      });
      return grading;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to fetch grading system" });
    }
  });

  // Add Grading Rule
  app.post("/api/admin/grading", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN" && request.user.role !== "SUPERADMIN") {
      return reply.code(403).send({ error: "Forbidden" });
    }
    const schoolId = request.user.schoolId;
    const { grade, minScore, maxScore, remark } = request.body;

    try {
      const newGrade = await prisma.gradingSystem.create({
        data: {
          grade,
          minScore: parseInt(minScore),
          maxScore: parseInt(maxScore),
          remark,
          schoolId
        }
      });
      return newGrade;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to create grading rule" });
    }
  });

  // Update Grading Rule
  app.put("/api/admin/grading/:id", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN" && request.user.role !== "SUPERADMIN") {
      return reply.code(403).send({ error: "Forbidden" });
    }
    const { id } = request.params;
    const schoolId = request.user.schoolId;
    const { grade, minScore, maxScore, remark } = request.body;

    try {
      const updatedGrade = await prisma.gradingSystem.update({
        where: { id, schoolId },
        data: {
          grade,
          minScore: parseInt(minScore),
          maxScore: parseInt(maxScore),
          remark
        }
      });
      return updatedGrade;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to update grading rule" });
    }
  });

  // Delete Grading Rule
  app.delete("/api/admin/grading/:id", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN" && request.user.role !== "SUPERADMIN") {
      return reply.code(403).send({ error: "Forbidden" });
    }
    const { id } = request.params;
    const schoolId = request.user.schoolId;

    try {
      await prisma.gradingSystem.delete({
        where: { id, schoolId }
      });
      return { success: true };
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to delete grading rule" });
    }
  });

  // --- Student Results Routes ---

  // Record Student Result
  app.post("/api/admin/results", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN" && request.user.role !== "TEACHER" && request.user.role !== "SUPERADMIN") {
      return reply.code(403).send({ error: "Forbidden" });
    }
    const schoolId = request.user.schoolId;
    const { studentId, subject, marks, term, class: studentClass } = request.body;

    try {
      const result = await prisma.studentResult.create({
        data: {
          studentId,
          subject,
          marks: parseFloat(marks),
          term,
          class: studentClass,
          schoolId
        }
      });
      return result;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to record student result" });
    }
  });

  // List Student Results (for Admin/Teacher)
  app.get("/api/admin/results", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN" && request.user.role !== "TEACHER" && request.user.role !== "SUPERADMIN") {
      return reply.code(403).send({ error: "Forbidden" });
    }
    const schoolId = request.user.schoolId;
    const { studentClass, term, subject } = request.query;

    const where = { schoolId };
    if (studentClass) where.class = studentClass;
    if (term) where.term = term;
    if (subject) where.subject = subject;

    try {
      const results = await prisma.studentResult.findMany({
        where,
        include: {
          student: {
            select: { firstName: true, lastName: true, studentId: true }
          }
        },
        orderBy: { createdAt: 'desc' }
      });
      return results;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to fetch student results" });
    }
  });

  // --- Settings & Profile Routes (Admin) ---

  // Get School Details
  app.get("/api/admin/school", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN") return reply.code(403).send({ error: "Forbidden" });
    const schoolId = request.user.schoolId;

    try {
      const school = await prisma.school.findUnique({
        where: { id: schoolId }
      });
      return school;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to fetch school details" });
    }
  });

  // Update School Details
  app.put("/api/admin/school", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN") return reply.code(403).send({ error: "Forbidden" });
    const schoolId = request.user.schoolId;
    const { name, address, phone, email } = request.body;

    try {
      const updatedSchool = await prisma.school.update({
        where: { id: schoolId },
        data: { name, address, phone, email }
      });
      return updatedSchool;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to update school details" });
    }
  });

  // Get Admin Profile
  app.get("/api/admin/profile", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN") return reply.code(403).send({ error: "Forbidden" });

    try {
      const user = await prisma.user.findUnique({
        where: { id: request.user.id },
        select: { id: true, email: true, firstName: true, lastName: true, role: true, phone: true, address: true, createdAt: true }
      });
      return user;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to fetch profile" });
    }
  });

  // Update Admin Profile
  app.put("/api/admin/profile", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN") return reply.code(403).send({ error: "Forbidden" });
    const { firstName, lastName, phone, address, email } = request.body;

    try {
      const user = await prisma.user.update({
        where: { id: request.user.id },
        data: { firstName, lastName, phone, address, email }
      });
      return { message: "Profile updated successfully", user: { firstName: user.firstName, lastName: user.lastName, email: user.email } };
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to update profile" });
    }
  });

  // Change Admin Password
  app.post("/api/admin/change-password", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "ADMIN") return reply.code(403).send({ error: "Forbidden" });
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
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to change password" });
    }
  });

  // --- Teacher Specialized Routes ---

  // Get Students Offering Teacher's Subjects
  app.get("/api/teacher/students", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "TEACHER") {
      return reply.code(403).send({ error: "Forbidden" });
    }

    const { subject } = request.query;
    const schoolId = request.user.schoolId;

    try {
      // Get teacher's subjects
      const teacher = await prisma.user.findUnique({
        where: { id: request.user.id },
        select: { subjects: true }
      });

      if (!teacher || !teacher.subjects || teacher.subjects.length === 0) {
        return [];
      }

      // Determine which subjects to filter by
      const filterSubjects = subject ? [subject] : teacher.subjects;

      // Find students in the same school who offer at least one of these subjects
      const students = await prisma.user.findMany({
        where: {
          schoolId,
          role: "STUDENT",
          isActive: true,
          subjects: {
            hasSome: filterSubjects
          }
        },
        select: {
          id: true,
          firstName: true,
          lastName: true,
          email: true,
          studentId: true,
          studentClass: true,
          subjects: true,
          phone: true,
          address: true
        },
        orderBy: [
          { studentClass: 'asc' },
          { lastName: 'asc' }
        ]
      });

      return {
        students,
        teacherSubjects: teacher.subjects
      };
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to fetch students" });
    }
  });

  // --- Teacher Tool Routes ---

  // Lesson Notes
  app.get("/api/teacher/lesson-notes", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "TEACHER" && request.user.role !== "ADMIN") return reply.code(403).send({ error: "Forbidden" });
    const teacherId = request.user.id;
    try {
      const notes = await prisma.lessonNote.findMany({
        where: { teacherId },
        orderBy: { createdAt: 'desc' }
      });
      return notes;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to fetch lesson notes" });
    }
  });

  app.post("/api/teacher/lesson-notes", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "TEACHER") return reply.code(403).send({ error: "Forbidden" });
    const { subject, topic, content, class: studentClass } = request.body;
    try {
      const note = await prisma.lessonNote.create({
        data: {
          subject,
          topic,
          content,
          class: studentClass,
          teacherId: request.user.id,
          schoolId: request.user.schoolId
        }
      });
      return note;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to create lesson note" });
    }
  });

  // AI Lesson Note Generation (Placeholder/Mock)
  app.post("/api/teacher/lesson-notes/generate", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "TEACHER") return reply.code(403).send({ error: "Forbidden" });
    const { subject, topic, class: studentClass } = request.body;

    try {
      // Mocking AI response for now. In a real scenario, we'd call OpenAI/DeepSeek API here.
      const aiContent = `
        <h3>Lesson Plan: ${topic} (${subject})</h3>
        <p><strong>Objective:</strong> Students will understand the core concepts of ${topic}.</p>
        <p><strong>Outline:</strong></p>
        <ul>
          <li>Introduction to ${topic}</li>
          <li>Key Mechanisms and Principles</li>
          <li>Real-world applications</li>
          <li>Conclusion and Review</li>
        </ul>
        <p>This note was generated via AI based on your topic and subject for ${studentClass}.</p>
      `;

      return { content: aiContent };
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "AI Generation failed" });
    }
  });

  // Gemini AI Chat
  const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
  const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });

  app.post("/api/teacher/ai/chat", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "TEACHER") return reply.code(403).send({ error: "Forbidden" });
    const { message } = request.body;

    try {
      const prompt = `You are a professional educational assistant for a school management system. 
      Help the teacher with their request: "${message}". 
      If they want a lesson note, provide a structured note with Introduction, Core Content, and Summary.
      If they want exam questions, provide clear and challenging questions.
      Keep the tone professional and helpful.`;

      const result = await model.generateContent(prompt);
      const response = await result.response;
      const text = response.text();

      return { reply: text };
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "AI Assistant is temporarily unavailable. Please try again." });
    }
  });

  // Assignments
  app.get("/api/teacher/assignments", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "TEACHER" && request.user.role !== "ADMIN" && request.user.role !== "STUDENT") {
      return reply.code(403).send({ error: "Forbidden" });
    }
    const { class: studentClass } = request.query;
    const where = { schoolId: request.user.schoolId };

    if (request.user.role === "TEACHER") {
      where.teacherId = request.user.id;
    } else if (request.user.role === "STUDENT") {
      where.class = request.user.studentClass;
    } else if (studentClass) {
      where.class = studentClass;
    }

    try {
      const assignments = await prisma.assignment.findMany({
        where,
        orderBy: { createdAt: 'desc' }
      });
      return assignments;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to fetch assignments" });
    }
  });

  app.post("/api/teacher/assignments", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "TEACHER") return reply.code(403).send({ error: "Forbidden" });
    const { title, description, dueDate, class: studentClass, subject } = request.body;
    try {
      const assignment = await prisma.assignment.create({
        data: {
          title,
          description,
          dueDate: new Date(dueDate),
          class: studentClass,
          subject,
          teacherId: request.user.id,
          schoolId: request.user.schoolId
        }
      });
      return assignment;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to create assignment" });
    }
  });

  // Exam Questions
  app.get("/api/teacher/exams/questions", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "TEACHER" && request.user.role !== "ADMIN") return reply.code(403).send({ error: "Forbidden" });
    const { subject, class: studentClass, term } = request.query;
    const where = { schoolId: request.user.schoolId };
    if (subject) where.subject = subject;
    if (studentClass) where.class = studentClass;
    if (term) where.term = term;

    try {
      const questions = await prisma.examQuestion.findMany({
        where,
        orderBy: { createdAt: 'asc' }
      });
      return questions;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to fetch exam questions" });
    }
  });

  app.post("/api/teacher/exams/questions", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "TEACHER") return reply.code(403).send({ error: "Forbidden" });
    const { subject, class: studentClass, type, question, options, answer, marks, term } = request.body;
    try {
      const examQuestion = await prisma.examQuestion.create({
        data: {
          subject,
          class: studentClass,
          type,
          question,
          options,
          answer,
          marks: parseFloat(marks) || 1.0,
          term,
          teacherId: request.user.id,
          schoolId: request.user.schoolId
        }
      });
      return examQuestion;
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to create exam question" });
    }
  });

  // Bulk Upload Exam Questions (DOCX)
  app.post("/api/teacher/exams/bulk-upload", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "TEACHER") return reply.code(403).send({ error: "Forbidden" });
    const data = await request.file();
    if (!data) return reply.code(400).send({ error: "No file provided" });

    try {
      const buffer = await data.toBuffer();
      const result = await mammoth.extractRawText({ buffer });
      const text = result.value;

      // Basic parsing logic: Split by lines, look for question patterns
      // This is a naive implementation; ideally, we'd use AI or more robust patterns
      const lines = text.split('\n').filter(l => l.trim() !== '');
      const questions = [];
      let currentQuestion = null;

      for (const line of lines) {
        if (line.match(/^\d+\./)) { // Starts with "1." or "2." etc.
          if (currentQuestion) questions.push(currentQuestion);
          currentQuestion = {
            question: line.replace(/^\d+\.\s*/, ''),
            type: "MCQ",
            options: [],
            answer: "",
            marks: 1
          };
        } else if (line.match(/^[A-D]\)/) || line.match(/^[A-D]\./)) {
          if (currentQuestion) {
            currentQuestion.options.push(line.replace(/^[A-D][\.\)]\s*/, ''));
          }
        }
      }
      if (currentQuestion) questions.push(currentQuestion);

      return { questions };
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to parse document" });
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

  // Get Student Results
  app.get("/api/student/results", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (request.user.role !== "STUDENT") {
      return reply.code(403).send({ error: "Forbidden" });
    }

    try {
      const results = await prisma.studentResult.findMany({
        where: { studentId: request.user.id },
        orderBy: { createdAt: 'desc' }
      });

      const grading = await prisma.gradingSystem.findMany({
        where: { schoolId: request.user.schoolId },
        orderBy: { minScore: 'desc' }
      });

      return {
        results,
        grading
      };
    } catch (err) {
      app.log.error(err);
      return reply.code(500).send({ error: "Failed to fetch results" });
    }
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