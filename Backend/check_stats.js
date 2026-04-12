
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

async function check() {
  try {
    const schools = await prisma.school.findMany({
      include: {
        _count: {
          select: {
            users: true,
            examSchedules: true,
            subjects: true
          }
        }
      }
    });

    console.log("Schools Summary:");
    schools.forEach(s => {
      console.log(`School: ${s.name} (id: ${s.id}, number: ${s.schoolNumber})`);
      console.log(`- Users: ${s._count.users}`);
      console.log(`- Subjects: ${s._count.subjects}`);
    });

    const users = await prisma.user.findMany({
      select: {
        email: true,
        role: true,
        schoolId: true
      }
    });

    console.log("\nUsers Summary:");
    users.forEach(u => {
      console.log(`User: ${u.email}, Role: ${u.role}, schoolId: ${u.schoolId}`);
    });

  } catch (err) {
    console.error(err);
  } finally {
    await prisma.$disconnect();
  }
}

check();
