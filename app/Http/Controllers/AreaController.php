<?php

namespace App\Http\Controllers;

use App\Models\Area;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class AreaController extends Controller
{

    // Método para obtener todas las áreas
    public function index()
    {
        try {
             // Obtener todas las áreas
            $areas = Area::all();
            // Devolver las áreas en formato JSON con estado 200 (OK)
            return response()->json([
                'status' => true,
                'data' => $areas
            ],200);
        } catch (\Throwable $th) {
            // En caso de error, devolver un mensaje de error en formato JSON
            return response()->json([
                'status' => false,
                'message' => $th
            ]);
        }
    }

    // Método para almacenar una nueva área
    public function store(Request $request)
    {
        // Reglas de validación para los campos de entrada
        $rules = [
            'are_name' => 'required|string|min:1|unique:areas|max:255|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
            'use_id' =>'required|integer|exists:users'
        ];

         // Validar la solicitud de entrada según las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        // Si la validación falla, devolver los errores en formato JSON
        if ($validator->fails()) {
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ]);
        }else{
            // Crear una nueva área con los datos validados
            $area = new Area($request->input());
            $area->save();

            // Registrar el nuevo registro en el log (función personalizada)
            Controller::NewRegisterTrigger("Se creo un registro en la tabla Area: $request->are_name",3,$request->use_id);

            // Devolver un mensaje de éxito en formato JSON
            return response()->json([
                'status' => True,
                'message' => "The area: ".$area->are_name." has been created successfully."
            ],200);
        }
    }

     // Método para mostrar una área específica por su ID
    public function show($id)
    {

        // Buscar el área por su ID
        $area = Area::find($id);

        // Si no se encuentra el área, devolver un mensaje de error en formato JSON
        if ($area == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'the area requested was not found']
            ],400);
        }else{
            // Si se encuentra el área, devolverla en formato JSON con estado 200 (OK)
            return response()->json([
                'status' => true,
                'data' => $area
            ]);
        }
    }

    // Método para actualizar una área existente
    public function update(Request $request, $id)
    {
        // Buscar el área por su ID
        $area = Area::find($id);

        // Si no se encuentra el área, devolver un mensaje de error en formato JSON
        if ($area == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'the area requested was not found']
            ],400);
        }else{

            // Reglas de validación para los campos de entrada
            $rules = [
                'are_name' => 'required|string|min:1|max:255|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
                'use_id' =>'required|integer|exists:users'
            ];

            // Validar la solicitud de entrada según las reglas definidas
            $validator = Validator::make($request->input(), $rules);

            // Validar si el valor existe en la base de datos para actualizar
            $validate = Controller::validate_exists($request->are_name, 'areas', 'are_name', 'are_id', $id);

            // Si la validación falla o el valor ya existe, devolver un mensaje de error en formato JSON
            if ($validator->fails() || $validate == 0) {
                $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
                return response()->json([
                    'status' => False,
                    'message' => $msg
                ]);
            }else{
                // Actualizar los valores del área
                $area->are_name = $request->are_name;
                $area->save();

                // Registrar la actualización en el log (función personalizada)
                Controller::NewRegisterTrigger("Se realizo una Edicion de datos en la tabla Area del dato: id->$id",1,$request->use_id);

                 // Devolver un mensaje de éxito en formato JSON
                return response()->json([
                    'status' => True,
                    'message' => "The area: ".$area->are_name." has been update successfully."
                ],200);
            }
        }
    }

    // Método para eliminar una área (no disponible)
    public function destroy(Area $areas)
    {

        // Devolver un mensaje de función no disponible en formato JSON
        return response()->json([
            'status' => false,
            'message' => "FUNCTION NOT AVAILABLE"
        ],400);
    }
}
