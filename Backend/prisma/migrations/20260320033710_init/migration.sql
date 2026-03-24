/*
  Warnings:

  - A unique constraint covering the columns `[student_id]` on the table `users` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "public"."schools" ADD COLUMN     "last_reactivated_at" TIMESTAMP(3),
ADD COLUMN     "valid_until" TIMESTAMP(3) NOT NULL DEFAULT NOW() + interval '4 months';

-- AlterTable
ALTER TABLE "public"."users" ADD COLUMN     "is_email_verified" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "student_class" TEXT,
ADD COLUMN     "student_id" TEXT,
ADD COLUMN     "subjects" TEXT[],
ADD COLUMN     "two_factor_code" TEXT,
ADD COLUMN     "two_factor_expires" TIMESTAMP(3),
ADD COLUMN     "verification_code" TEXT;

-- CreateTable
CREATE TABLE "public"."subjects" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "section" TEXT NOT NULL,
    "category" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "subjects_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."exam_schedules" (
    "id" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "class" TEXT NOT NULL,
    "date" TEXT NOT NULL,
    "time" TEXT NOT NULL,
    "duration" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "school_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "exam_schedules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."grading_systems" (
    "id" TEXT NOT NULL,
    "grade" TEXT NOT NULL,
    "min_score" INTEGER NOT NULL,
    "max_score" INTEGER NOT NULL,
    "remark" TEXT,
    "school_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "grading_systems_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."student_results" (
    "id" TEXT NOT NULL,
    "student_id" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "marks" DOUBLE PRECISION NOT NULL,
    "testScore" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "term" TEXT NOT NULL,
    "class" TEXT NOT NULL,
    "school_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "student_results_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."lesson_notes" (
    "id" TEXT NOT NULL,
    "teacher_id" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "topic" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "class" TEXT NOT NULL,
    "school_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "lesson_notes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."assignments" (
    "id" TEXT NOT NULL,
    "teacher_id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "due_date" TIMESTAMP(3) NOT NULL,
    "class" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "school_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "assignments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."exam_questions" (
    "id" TEXT NOT NULL,
    "teacher_id" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "class" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "question" TEXT NOT NULL,
    "options" JSONB,
    "answer" TEXT NOT NULL,
    "marks" DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    "term" TEXT NOT NULL,
    "school_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "exam_questions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."student_answers" (
    "id" TEXT NOT NULL,
    "result_id" TEXT NOT NULL,
    "question_id" TEXT NOT NULL,
    "answer_text" TEXT NOT NULL,
    "isCorrect" BOOLEAN DEFAULT false,
    "marks" DOUBLE PRECISION DEFAULT 0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "student_answers_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "subjects_name_key" ON "public"."subjects"("name");

-- CreateIndex
CREATE UNIQUE INDEX "users_student_id_key" ON "public"."users"("student_id");

-- AddForeignKey
ALTER TABLE "public"."exam_schedules" ADD CONSTRAINT "exam_schedules_school_id_fkey" FOREIGN KEY ("school_id") REFERENCES "public"."schools"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."grading_systems" ADD CONSTRAINT "grading_systems_school_id_fkey" FOREIGN KEY ("school_id") REFERENCES "public"."schools"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."student_results" ADD CONSTRAINT "student_results_student_id_fkey" FOREIGN KEY ("student_id") REFERENCES "public"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."lesson_notes" ADD CONSTRAINT "lesson_notes_teacher_id_fkey" FOREIGN KEY ("teacher_id") REFERENCES "public"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."lesson_notes" ADD CONSTRAINT "lesson_notes_school_id_fkey" FOREIGN KEY ("school_id") REFERENCES "public"."schools"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."assignments" ADD CONSTRAINT "assignments_teacher_id_fkey" FOREIGN KEY ("teacher_id") REFERENCES "public"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."assignments" ADD CONSTRAINT "assignments_school_id_fkey" FOREIGN KEY ("school_id") REFERENCES "public"."schools"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."exam_questions" ADD CONSTRAINT "exam_questions_teacher_id_fkey" FOREIGN KEY ("teacher_id") REFERENCES "public"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."exam_questions" ADD CONSTRAINT "exam_questions_school_id_fkey" FOREIGN KEY ("school_id") REFERENCES "public"."schools"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."student_answers" ADD CONSTRAINT "student_answers_result_id_fkey" FOREIGN KEY ("result_id") REFERENCES "public"."student_results"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."student_answers" ADD CONSTRAINT "student_answers_question_id_fkey" FOREIGN KEY ("question_id") REFERENCES "public"."exam_questions"("id") ON DELETE CASCADE ON UPDATE CASCADE;
