<?php

namespace App\Http\Controllers;

use App\Models\Student;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;

class StudentController extends Controller
{
    public function index()
    {
        // Obtener los estudiantes de la vista 'viewStudents'
        $lastStudents = DB::table('viewStudents')->get();
        $students = array();

        // Iterar sobre los estudiantes obtenidos
        foreach ($lastStudents as $student) {
            // Buscar el estudiante en la tabla 'students' por su ID
            $data = Student::find($student->stu_id);
            // Obtener la última inscripción del estudiante
            $lastEnrollment = $data->lastEnrollments();

            // Si no hay inscripción encontrada, agregar un mensaje de falta de inscripción
            if (is_null($lastEnrollment)) {
                $student->Enrollment = "Missing Enrollment";
                array_push($students, $student);
            } else {
                array_push($students, $lastEnrollment);
            }
        }

        // Retornar respuesta JSON con el estado y los datos de los estudiantes
        return response()->json([
            'status' => true,
            'data' => $students,
        ], 200);
    }
    
    public function indexAmount()
    {
        // Obtener los estudiantes de la vista 'viewStudents'
        $lastStudents = DB::table('viewStudents')->orderBy('stu_id', 'desc')->take(50)->get();
        $students = array();

        // Iterar sobre los estudiantes obtenidos
        foreach ($lastStudents as $student) {
            // Buscar el estudiante en la tabla 'students' por su ID
            $data = Student::find($student->stu_id);
            // Obtener la última inscripción del estudiante
            $lastEnrollment = $data->lastEnrollments();

            // Si no hay inscripción encontrada, agregar un mensaje de falta de inscripción
            if (is_null($lastEnrollment)) {
                $student->Enrollment = "Missing Enrollment";
                array_push($students, $student);
            } else {
                array_push($students, $lastEnrollment);
            }
        }

        // Retornar respuesta JSON con el estado y los datos de los estudiantes
        return response()->json([
            'status' => true,
            'data' => $students,
        ], 200);
    }
    public function store(Request $request)
    {
        // Reglas de validación para los datos de entrada del estudiante
        $rules = [
            'stu_stratum' => 'required',
            'stu_military' => 'nullable|numeric|min:1',
            'stu_piar' => 'nullable|string|min:1|max:50|regex:/^[a-zA-Z0-9nÑÁÉÍÓÚÜáéíóúü\s\-,.;]+$/',
            'stu_typ_id' => 'required|integer|exists:students_types',
            'per_id' => 'required|integer|exists:persons',
            'loc_id' => 'required|integer|exists:localities',
            'mon_sta_id' => 'required|integer|exists:monetary_states',
            'use_id' => 'required|integer|exists:users'
        ];

        // Validar los datos de entrada con las reglas definidas
        $validator = Validator::make($request->all(), $rules);
        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->all()
            ]);
        }

        // Verificar si ya existe un estudiante con el mismo ID de persona (per_id)
        $existingStudent = Student::where('per_id', $request->per_id)->first();
        if ($existingStudent) {
            return response()->json([
                'status' => false,
                'message' => "The student already exists"
            ]);
        }

        // Asignar valores predeterminados si los campos militares o Piar están vacíos o nulos
        $request->merge([
            'stu_military' => is_null($request->input('stu_military')) || $request->input('stu_military') === '' ? 'N/A' : $request->input('stu_military'),
            'stu_piar' => is_null($request->input('stu_piar')) || $request->input('stu_piar') === '' ? 'N/A' : $request->input('stu_piar')
        ]);

        // Crear una nueva instancia de Student con los datos del request
        $student = new Student($request->all());
        $student->save(); // Guardar el estudiante en la base de datos
        $stu_id = $student->stu_id; // Obtener el ID del estudiante creado
        $request->merge(['stu_id' => $stu_id]); // Agregar el ID del estudiante al request

        // Obtener los datos de la persona asociada al estudiante
        $person = DB::table('persons')->where('per_id', $student->per_id)->first();
        // Registrar la acción en el sistema de trazabilidad
        Controller::NewRegisterTrigger("Se realizo una inserción en la tabla students", 3, $request->use_id);

        // Retornar respuesta JSON con el estado y el ID del estudiante creado
        return response()->json([
            'status' => true,
            'stu_id' => $student->stu_id,
            'message' => "The student '" . $person->per_name . "' has been added successfully."
        ], 200);
    }

    public function show($student)
    {
        // Buscar al estudiante por su ID en la base de datos
        $students = Student::search($student);

        // Verificar si la beca no existe y retornar un mensaje de error si es así
        if (!$students) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the students you are looking for'],
            ], 400);
        } else {
            // Retornar una respuesta JSON con los detalles de la beca encontrada

            return response()->json([
                'status' => true,
                'data' => $students,
            ], 200);
        }
    }
    public function update(Request $request, $student)
    {
        // Reglas de validación para los datos de entrada del estudiante a actualizar
        $rules = [
            'stu_stratum' => 'required',
            'stu_military' => 'nullable|numeric|min:1|max:9999999999',
            'stu_piar' => 'nullable|string|min:1|max:50|regex:/^[a-zA-Z0-9nÑÁÉÍÓÚÜáéíóúü\s\-,.;]+$/',
            'stu_typ_id' => 'required|integer|exists:students_types',
            'per_id' => 'required|integer|exists:persons',
            'loc_id' => 'required|integer|exists:localities',
            'mon_sta_id' => 'required|integer|exists:monetary_states',
        ];

        // Validar los datos de entrada con las reglas definidas
        $validator = Validator::make($request->input(), $rules);
        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->all()
            ]);
        } else {
            // Asignar valores predeterminados si los campos militares o Piar están vacíos o nulos
            $request->merge([
                'stu_military' => is_null($request->input('stu_military')) || $request->input('stu_military') === '' ? 'N/A' : $request->input('stu_military'),
                'stu_piar' => is_null($request->input('stu_piar')) || $request->input('stu_piar') === '' ? 'N/A' : $request->input('stu_piar')
            ]);

            // Buscar el estudiante por su ID y actualizar los datos con los del request
            $students = Student::find($student);
            $students->stu_stratum = $request->stu_stratum;
            $students->stu_typ_id = $request->stu_typ_id;
            $students->stu_piar = $request->stu_piar;
            $students->stu_military = $request->stu_military;
            $students->per_id = $request->per_id;
            $students->loc_id = $request->loc_id;
            $students->mon_sta_id = $request->mon_sta_id;
            $students->save(); // Guardar los cambios en la base de datos

            // Obtener los datos de la persona asociada al estudiante
            $person = DB::table('persons')->where('per_id', '=', $students->per_id)->first();
            // Registrar la acción en el sistema de trazabilidad
            Controller::NewRegisterTrigger("Se realizo una edición en la tabla students", 1, $request->use_id);

            // Retornar respuesta JSON con el estado y el mensaje de éxito
            return response()->json([
                'status' => true,
                'data' => "The student with ID: " . $students->stu_id . " has been updated to '" . $person->per_name . "' successfully.",
            ], 200);
        }
    }
    public function destroy(Student $student)
    {
        // Retornar una respuesta JSON indicando que la función no está disponible
        return response()->json([
            'status' => false,
            'message' => "Function not available."
        ], 400);
    }
    public function viewForDocumentStudent(Request $request)
    {
        // Llamar a un método en el modelo Student para obtener los detalles del estudiante
        $student = Student::viewForDocumentStudent($request);
        // Retornar una respuesta JSON con el estado y los datos del estudiante
        return response()->json([
            'status' => true,
            'data' => $student
        ], 200);
    }
}
