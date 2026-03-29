const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function check() {
  console.log('--- Prisma Model Check ---');
  try {
    // Check if calculatorEnabled exists in the generated DMMF
    const dmmf = prisma._baseClient._dmmf;
    const model = dmmf.datamodel.models.find(m => m.name === 'ExamQuestion');
    console.log('ExamQuestion Fields:', model.fields.map(f => f.name));
    
    if (model.fields.some(f => f.name === 'calculatorEnabled')) {
      console.log('SUCCESS: calculatorEnabled is found in the current Prisma Client generation.');
    } else {
      console.log('FAILURE: calculatorEnabled is NOT in the current Prisma Client generation.');
    }
  } catch (err) {
    console.error('Diagnostic error:', err);
  } finally {
    await prisma.$disconnect();
  }
}

check();
