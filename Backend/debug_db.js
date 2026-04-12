const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function check() {
  try {
    const schools = await prisma.school.findMany();
    const subsects = await prisma.subject.findMany({ select: { id: true, name: true, schoolId: true } });
    const users = await prisma.user.findMany({ select: { id: true, email: true, role: true, schoolId: true } });
    
    console.log("--- SCHOOLS ---");
    console.log(JSON.stringify(schools, null, 2));
    console.log("\n--- SUBJECTS (first 5) ---");
    console.log(JSON.stringify(subsects.slice(0, 5), null, 2));
    console.log(`Total subjects: ${subsects.length}`);
    console.log(`Subjects with schoolId null: ${subsects.filter(s => !s.schoolId).length}`);
    
    console.log("\n--- USERS (Admins/Teachers) ---");
    console.log(JSON.stringify(users.filter(u => u.role === 'ADMIN' || u.role === 'TEACHER'), null, 2));
    
  } catch (e) {
    console.error(e);
  } finally {
    await prisma.$disconnect();
  }
}

check();
