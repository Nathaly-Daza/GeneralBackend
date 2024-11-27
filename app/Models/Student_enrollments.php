<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class Student_enrollments extends Model
{
    use HasFactory;

    // Nombre de la tabla en la base de datos
    protected $table = 'student_enrollments';

    // Define la clave primaria personalizada
    protected $primaryKey = 'stu_enr_id';

    // Atributos que se pueden asignar en masa
    protected $fillable = [
        'stu_enr_semester',
        'stu_enr_status',
        'stu_enr_date',
        'stu_enr_journey',
        'peri_id',
        'stu_id',
        'car_id',
        'pro_id',
        'pha_id'
    ];

    // Indica que el modelo no utiliza marcas de tiempo
    public $timestamps = false;

        // Método para seleccionar todos los registros de matrículas con transformaciones

    public static function select(){
        $datas = DB::select("SELECT *
        FROM viewEnrollments");

        // Arreglos para almacenar matrículas por tipo de estado
        $enrollmentsType0 = []; // Inactivo
        $enrollmentsType1 = []; // Activo
        $enrollmentsType2 = []; // Pospuesto

        foreach($datas as $data){
            $data->status_name = Student_enrollments::getStatusName($data->stu_enr_status);
            $data->journey_name = Student_enrollments::getJourneyName($data->stu_enr_journey);
            // Clasifica las matrículas según su estado
            if ($data->stu_enr_status == 0) {
                $enrollmentsType0[] = $data; // Inactivo
            } elseif ($data->stu_enr_status == 1) {
                $enrollmentsType1[] = $data; // Activo
            } elseif ($data->stu_enr_status == 3) {
                $enrollmentsType2[] = $data; // Pospuesto
            }

        }
        return[
            'enrollment_Active'=>$enrollmentsType1,
            'enrollment_Inactive'=>$enrollmentsType0,
            'enrollment_Postpone'=>$enrollmentsType2,



        ];
    }
    // Método para obtener el nombre de la jornada según el código

    public static function getJourneyName($journey){
        switch($journey){
            case 0:
                return 'Diurno';
            case 1:
                return 'Nocturno';
        }
    }
        // Método para obtener el nombre del estado según el código

    public static function getStatusName($status) {
        switch ($status) {
            case 0:
                return 'Inactive';
            case 1:
                return 'Active';
            case 2:
                return 'Postpone';
        }
    }

        // Método para obtener matrículas inactivas

    public static function inactive(){
        $data = DB::select("SELECT *
        FROM viewEnrollments
        WHERE stu_enr_status=0;
         ");
        return $data;
    }

    // Método para buscar una matrícula activa por documento de identidad

    public static function search($id)
{
    $data = DB::select("SELECT *
        FROM viewEnrollments
        WHERE per_document = $id AND stu_enr_status = 1");

    $data[0]->stu_enr_journey = Student_enrollments::getJourneyName($data[0]->stu_enr_journey);
    if (!empty($data)) {
        $enrollment = $data[0];

        if ($enrollment->stu_enr_status == 0) {
            return [
                'stu_enr_id' => $enrollment->stu_enr_id,
                'message' => 'This enrollment is inactive.'
            ];
        } else {
            return $enrollment;
        }
    } else {
        return null;
    }
}

    }

