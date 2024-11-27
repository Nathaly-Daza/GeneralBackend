<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class Student extends Model
{
    use HasFactory;
    // Nombre de la tabla en la base de datos

    protected $table = 'students';

    // Define la clave primaria personalizada

    protected $primaryKey = 'stu_id';
    // Atributos que se pueden asignar en masa

    protected $fillable = [
        'stu_stratum',
        'stu_military',
        'stu_typ_id',
        'stu_piar',
        'per_id',
        'loc_id',
        'mon_sta_id'
    ];
    public $timestamps = false;

    // Método para buscar un estudiante por número de documento


    public static function search($id)
    {

        // Buscar el estudiante por número de documento en la vista viewEnrollments

        $student = DB::table('viewEnrollments')->where('per_document', '=', $id)->first();

        // Si no se encuentra ningún estudiante, retornar null

        if ($student == []) {
            return $student;
        }
        // Obtener el objeto Student por su id

        $students = Student::find($student->stu_id);

        // Agregar información adicional al objeto $student

        $student->semester = $students->lastEnrollments();
        $student->personal_contacts = $students->personalContacts();
        $student->emergency_contacts = $students->emergencyContacts();
        $student->medical_info = $students->medicalInfo();
        $student->use_photo = base64_decode($student->use_photo);
        return $student;
    }

    // Método para obtener la última matrícula del estudiante

    public function lastEnrollments()
    { //traiga
        $data = DB::table('viewEnrollments')
            ->where('stu_id', $this->stu_id)
            ->orderBy('stu_enr_id', 'desc')
            ->first();
        return $data;
    }

    // Método para obtener los contactos personales del estudiante (teléfonos y correos)

    public function personalContacts()
    { //traiga
        $telephones = DB::table('students')
            ->select('telephones.*')
            ->join('persons as p1', 'p1.per_id', '=', 'students.per_id')
            ->join('telephones', 'telephones.per_id', '=', 'p1.per_id')
            ->where('students.stu_id', '=', $this->stu_id)
            ->get();
        $mails = DB::table('students')
            ->select('mails.*')
            ->join('persons as p1', 'p1.per_id', '=', 'students.per_id')
            ->join('mails', 'mails.per_id', '=', 'p1.per_id')
            ->where('students.stu_id', '=', $this->stu_id)
            ->get();
        $contacts = [
            'telephones' => $telephones,
            'mails' => $mails,
        ];
        return $contacts;
    }

    // Método para obtener los contactos de emergencia del estudiante

    public function emergencyContacts()
    { //traiga
        $data = DB::table('students')
            ->select('contacts.*', 'relationships.rel_name')
            ->join('persons as p1', 'p1.per_id', '=', 'students.per_id')
            ->join('contacts', 'contacts.per_id', '=', 'p1.per_id')
            ->join('relationships', 'relationships.rel_id', '=', 'contacts.rel_id')
            ->where('students.stu_id', '=', $this->stu_id)
            ->get();
        return $data;
    }
    // Método para obtener la información médica del estudiante (enfermedades y alergias)

    public function medicalInfo()
    {
        $diseases = DB::table('students')
            ->join('persons as p1', 'p1.per_id', '=', 'students.per_id')
            ->join('medical_histories', 'medical_histories.per_id', '=', 'p1.per_id')
            ->join('diseases', 'medical_histories.dis_id', '=', 'diseases.dis_id')
            ->select('diseases.*')
            ->where('students.stu_id', '=', $this->stu_id)
            ->get();

        $allergies = DB::table('students')
            ->join('persons as p1', 'p1.per_id', '=', 'students.per_id')
            ->join('allergy_histories', 'allergy_histories.per_id', '=', 'p1.per_id',)
            ->join('allergies', 'allergy_histories.all_id', '=', 'allergies.all_id')
            ->select('allergies.*')
            ->where('students.stu_id', '=', $this->stu_id)
            ->get();
        $data = [
            'diseases' => $diseases,
            'allergies' => $allergies,
        ];
        return $data;
    }

    // Método para obtener información completa del estudiante por número de documento y tipo de documento

    public static function viewForDocumentStudent($request)
    {
        try {
            // Buscar el estudiante por número de documento y tipo de documento en la vista viewStudents

            $student = DB::select("SELECT viewStudents.* FROM viewStudents
            WHERE viewStudents.per_document = ? AND viewStudents.doc_typ_id = ?", [$request->per_document, $request->doc_typ_id]);
            // Si no se encuentra ningún estudiante, retornar un mensaje indicando que no es estudiante

            if ($student == []) {
                return "the user not is a student";
            }

            // Obtener el historial de becas del estudiante

            $history_scholarships = DB::select("SELECT history_scholarships.*, scholarships.sch_name FROM history_scholarships INNER JOIN  scholarships ON history_scholarships.sch_id = scholarships.sch_id WHERE stu_id = ?", [$student[0]->stu_id]);
            // Obtener las matrículas activas del estudiante

            $student_enrollmentsOn = DB::table('viewEnrollments')->select('stu_enr_id', 'pha_name', 'stu_id', 'stu_enr_status', 'peri_name', 'stu_enr_semester', 'stu_enr_journey', 'pro_id', 'pro_name', 'car_name', 'stu_enr_date', 'car_name', 'car_id', 'peri_id', 'pha_id', 'peri_start', 'peri_end', 'car_typ_id', 'car_typ_name')->where('stu_enr_status', '=', 1)->where('stu_id', '=', $student[0]->stu_id)->get();
            // Obtener las matrículas inactivas del estudiante

            $student_enrollmentsOff = DB::table('viewEnrollments')->select('stu_enr_id', 'pha_name', 'stu_id', 'stu_enr_status', 'peri_name', 'stu_enr_semester', 'stu_enr_journey', 'pro_id', 'pro_name', 'car_name', 'stu_enr_date', 'car_name', 'car_id', 'peri_id', 'pha_id', 'peri_start', 'peri_end', 'car_typ_id', 'car_typ_name')->where('stu_enr_status', '=', 0)->where('stu_id', '=', $student[0]->stu_id)->get();
            // Decodificar la foto del estudiante (asumiendo que use_photo es un campo base64)

            $student[0]->use_photo = base64_decode($student[0]->use_photo);
            // Agregar información adicional al objeto $student

            $student[0]->history_scholarships = $history_scholarships;
            $student[0]->student_enrollmentsOn = $student_enrollmentsOn;
            $student[0]->student_enrollmentsOff = $student_enrollmentsOff;
            return $student[0];
        } catch (\Throwable $th) {
            // Manejar cualquier error que ocurra durante la búsqueda

            return response()->json([
                'status' => false,
                'message' => "Error occurred while found elements"
            ], 500);
        }
    }
}
