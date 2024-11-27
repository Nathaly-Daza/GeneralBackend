<?php

namespace App\Http\Controllers;

use App\Models\Student_enrollments;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;

class StudentEnrollmentsController extends Controller
{
    public function index()
    {
        try {
                        // Selección de todos los registros de inscripciones de estudiantes

            $students_enrollments = Student_enrollments::select();
                        // Retornar una respuesta JSON con el estado y los datos de las inscripciones

            return response()->json([
                'status' => true,
                'data' => $students_enrollments,
            ], 200);
        } catch (\Throwable $th) {
                        // Capturar cualquier excepción y devolver una respuesta JSON con estado falso y mensaje de error

            return response()->json([
                'status' => false,
                'message' => $th
            ], 500);
        }
    }
    public static function store(Request $request)
    {
                // Definir reglas de validación para los datos de la inscripción del estudiante

        $rules = [
            'stu_enr_semester' => 'required|numeric|max:7|min:1',
            'stu_enr_journey' => 'required|numeric|max:1|min:0',
            'stu_id' => 'required|exists:students',
            'peri_id' => 'required|exists:periods',
            'car_id' => 'required|exists:careers',
            'pro_id' => 'required|exists:promotions',
            'pha_id' => 'required|exists:phases',
            'use_id' => 'required|exists:users'

        ];
                // Validar los datos de entrada con las reglas definidas


        $validator = Validator::make($request->input(), $rules);

        if ($validator->fails()) {
                        // Retornar una respuesta JSON con estado falso y mensajes de error de validación

            return response()->json([
                'status' => false,
                'message' => $validator->errors()->all()
            ]);
        }
                // Verificar si ya existe un registro de inscripción con las mismas características


        $existingRecord = Student_enrollments::where('stu_enr_semester', $request->stu_enr_semester)
            ->where('stu_enr_journey', $request->stu_enr_journey)
            ->where('stu_id', $request->stu_id)
            ->where('peri_id', $request->peri_id)
            ->where('car_id', $request->car_id)
            ->where('pro_id', $request->pro_id)
            ->where('pha_id', $request->pha_id)

            ->where('stu_enr_status', 1)
            ->first();

        if ($existingRecord) {
                        // Retornar una respuesta JSON con estado falso y mensaje de conflicto si ya existe un registro similar

            return response()->json([
                'status' => false,
                'message' => 'A record with the same characteristics already exists.'
            ], 409);
        }
                // Crear una nueva instancia de Student_enrollments con los datos del request


        $students_enrollments = new Student_enrollments();
        $students_enrollments->stu_enr_semester = $request->stu_enr_semester;
        $students_enrollments->stu_enr_journey = $request->stu_enr_journey;
        $students_enrollments->stu_id = $request->stu_id;
        $students_enrollments->peri_id = $request->peri_id;
        $students_enrollments->car_id = $request->car_id;
        $students_enrollments->pro_id = $request->pro_id;
        $students_enrollments->pha_id = $request->pha_id;

        $students_enrollments->stu_enr_status = 1;
        $students_enrollments->stu_enr_date = now()->toDateString();
        $students_enrollments->save(); // Guardar el registro de inscripción en la base de datos

        //Se busca los registros de inscripcion antiguos en la base de datos
        $oldEnrollments = Student_enrollments::where('stu_id', $request->stu_id)
            ->where('stu_enr_status', 1)
            ->where('stu_enr_id', '!=', $students_enrollments->stu_enr_id)
            ->where('car_id', $students_enrollments->car_id)
            ->get();

            //Se cambia el estado de los registros de inscripcion antiguos a 0 (Desactivado)
        foreach ($oldEnrollments as $oldEnrollment) {
            $oldEnrollment->stu_enr_status = 0;
            $oldEnrollment->save();
        }



        // Obtener información del estudiante recién inscrito desde una vista y registrar la acción
        $student = DB::table('viewEnrollments')->where('stu_id', $request->stu_id)->first();
        Controller::NewRegisterTrigger("Se realizo una inserción en la tabla students_enrollments", 3, $request->use_id);

        // Retornar una respuesta JSON con estado verdadero, mensaje de éxito y datos de la inscripción
        return response()->json([
            'status' => true,
            'message' => "The enrollment of student '" . $student->per_name . "' in semester '" . $students_enrollments->stu_enr_semester . "' in the period '" . $student->peri_name . "' has been added successfully.",
            'data' => $students_enrollments->stu_enr_id
        ], 200);
    }

    public function show($id)
    {
        // Buscar inscripciones de estudiantes basadas en el ID proporcionado
        $students_enrollments = Student_enrollments::search($id);

        if ($students_enrollments == null) {
            // Retornar una respuesta JSON con estado falso y mensaje de error si no se encontraron inscripciones
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The student enrollments requested not found'],
            ], 400);
        } else {
            // Retornar una respuesta JSON con estado verdadero y datos de las inscripciones encontradas
            return response()->json([
                'status' => true,
                'data' => $students_enrollments,
            ], 200);
        }
    }
    public function update(Request $request, $id)
    {
        // Buscar la inscripción de estudiante por su ID
        $students_enrollments = Student_enrollments::find($id);

        // Definir reglas de validación para los datos de la inscripción del estudiante a actualizar
        $rules = [
            'stu_enr_semester' => 'required|numeric|max:7|min:1',
            'stu_enr_journey' => 'required|numeric|max:1|min:0',
            'peri_id' => 'required|exists:periods',
            'stu_id' => 'required|exists:students',
            'car_id' => 'required|exists:careers',
            'pro_id' => 'required|exists:promotions',
            'pha_id' => 'required|exists:phases',
            'use_id' => 'required|exists:users'
        ];

        // Validar los datos de entrada con las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        if ($validator->fails()) {
            // Retornar una respuesta JSON con estado falso y mensajes de error de validación
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->all()
            ]);
        } else {
            // Verificar si ya existe un registro de inscripción con las mismas características
            $existingRecord = Student_enrollments::where('stu_enr_semester', $request->stu_enr_semester)
                ->where('stu_enr_journey', $request->stu_enr_journey)
                ->where('stu_id', $request->stu_id)
                ->where('peri_id', $request->peri_id)
                ->where('car_id', $request->car_id)
                ->where('pro_id', $request->pro_id)
                ->where('pha_id', $request->pha_id)
                ->where('stu_enr_status', 1)
                ->first();

            if ($existingRecord) {
                // Retornar una respuesta JSON con estado falso y mensaje de conflicto si ya existe un registro similar
                return response()->json([
                    'status' => false,
                    'message' => 'A record with the same characteristics already exists.'
                ], 409);
            }

            // Actualizar los datos de la inscripción del estudiante con los del request
            $students_enrollments->stu_enr_semester = $request->stu_enr_semester;
            $students_enrollments->stu_enr_journey = $request->stu_enr_journey;
            $students_enrollments->peri_id = $request->peri_id;
            $students_enrollments->stu_id = $request->stu_id;
            $students_enrollments->car_id = $request->car_id;
            $students_enrollments->pro_id = $request->pro_id;
            $students_enrollments->pha_id = $request->pha_id;
            $students_enrollments->stu_enr_date = now()->toDateString();
            $students_enrollments->stu_enr_status = 1;

            // Guardar los cambios realizados en la inscripción del estudiante
            $students_enrollments->save();

            // Desactivar inscripciones antiguas del mismo estudiante para el mismo programa
            $oldEnrollments = Student_enrollments::where('stu_id', $request->stu_id)
                ->where('stu_enr_status', 1)
                ->where('stu_enr_id', '!=', $students_enrollments->stu_enr_id)
                ->where('car_id', $students_enrollments->car_id)
                ->get();

            foreach ($oldEnrollments as $oldEnrollment) {
                $oldEnrollment->stu_enr_status = 0;
                $oldEnrollment->save();
            }

            // Obtener información del estudiante actualizado desde una vista y registrar la acción
            $student = DB::table('viewEnrollments')->where('stu_id', $request->stu_id)->first();
            Controller::NewRegisterTrigger("Se realizo una edición en la tabla students enrollments", 4, $request->use_id);

            // Retornar una respuesta JSON con estado verdadero y mensaje de éxito
            return response()->json([
                'status' => true,
                'message' => "The enrollment of student '" . $student->per_name . "' in semester '" . $students_enrollments->stu_enr_semester . "' in the period '" . $student->peri_name . "' has been updated successfully.",
            ], 200);
        }
    }


    public function historyEnrollments()
    {
        try {
            // Obtener inscripciones de estudiantes inactivas
            $students_enrollments = Student_enrollments::inactive();

            // Retornar una respuesta JSON con estado verdadero y datos de las inscripciones inactivas
            return response()->json([
                'status' => true,
                'data' => $students_enrollments,
            ], 200);
        } catch (\Throwable $th) {
            // Capturar cualquier excepción y devolver una respuesta JSON con estado falso y mensaje de error
            return response()->json([
                'status' => false,
                'message' => $th
            ], 500);
        }
    }
    public function destroy(Request $request, $id)
    {
        // Buscar la inscripción de estudiante por su ID
        $studentE = Student_enrollments::find($id);

        // Cambiar el estado de la inscripción del estudiante
        $newSE = ($studentE->stu_enr_status == 0) ? 1 : 0;
        $studentE->stu_enr_status = $newSE;
        $studentE->save();

        // Registrar la acción de cambio de estado
        Controller::NewRegisterTrigger("An change status was made in the students enrollments table", 2, 6, $request->use_id);

        // Retornar una respuesta JSON con estado verdadero y mensaje de éxito
        return response()->json([
            'status' => true,
            'message' => 'The requested students enrollments has been change status successfully'
        ]);
    }
}
