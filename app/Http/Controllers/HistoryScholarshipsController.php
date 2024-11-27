<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Validator;

use App\Models\history_scholarships;
use Illuminate\Http\Request;

class HistoryScholarshipsController extends Controller
{
    public function index()
    {

        // Seleccionar todas las historias de becas
        $hScholar = history_scholarships::select();

        // Devolver una respuesta JSON con las historias de becas obtenidas
        return response()->json([
            'status' => true,
            'data' => $hScholar
        ], 200);
    }


    public function store(Request $request)
    {

        // Definir las reglas de validación para los datos de entrada
        $rules = [
            'sch_id' => 'required|numeric|exists:scholarships',
            'stu_id' => 'required|numeric|exists:students',
            'his_sch_start' => 'required|date',
            'his_sch_end' => 'date',
        ];

        // Validar los datos de entrada con las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        // Devolver una respuesta JSON con los errores de validación si falla la validación
        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->all()
            ]);
        }

        // Verificar si ya existe un registro con las mismas becas y estudiantes
        $existingRecord = history_scholarships::where('sch_id', $request->sch_id)
            ->where('stu_id', $request->stu_id)
            ->first();

        // Devolver un mensaje de error si ya existe un registro con las mismas becas y estudiantes
        if ($existingRecord) {
            return response()->json([
                'status' => false,
                'message' => 'A record with the same'
            ], 409);
        }


        // Crear un nuevo registro de historia de becas con los datos proporcionados
        $hScholar = new history_scholarships($request->input());
        $hScholar->save();

        // Disparar la accion de registro
        Controller::NewRegisterTrigger("An insertion was made in the scholarships Histories table '$hScholar->his_sch_id'", 3, $request->use_id);

        // Devolver una respuesta JSON indicando que se ha creado la historia de becas exitosamente
        return response()->json([
            'status' => true,
            'message' => "The scholarships history has been created successfully.",
            'data' => $hScholar->his_sch_id,
        ], 200);
    }


    public function show($id)
    {

        // Buscar una historia de becas por su ID
        $hScholar = history_scholarships::search($id);

        // Devolver un mensaje de error si no se encuentra la historia de becas solicitada
        if ($hScholar == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The requested scholarships Histories was not found']
            ], 400);
        } else {

            // Devolver una respuesta JSON con la historia de becas encontrada
            return response()->json([
                'status' => true,
                'data' => $hScholar
            ]);
        }
    }


    public function update(Request $request, $id)
    {

        // Devolver un mensaje de error indicando que la función no está disponible
        return response()->json([
            'status' => false,
            'message' => 'Function not available'
        ]);
    }

    public function destroy(Request $request, $id)
    {

        // Devolver un mensaje de error indicando que la función no está disponible
        return response()->json([
            'status' => false,
            'message' => 'Function not available'
        ]);
    }
}
