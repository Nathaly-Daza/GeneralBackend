<?php

namespace App\Http\Controllers;

use App\Models\CoreMaterial;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class CoreMaterialController extends Controller
{

    public function index()
    {

        // Selecciona todos los materiales principales
        $coreMaterial = CoreMaterial::select();

        // Si no hay materiales disponibles, devuelve un mensaje de error
        if($coreMaterial == null){
            return response()->json([
            'status' => False,
            'message' => 'There are no core materials available.'
            ],400);
        }else{

            // Devuelve los materiales principales si están disponibles
            return response()->json([
                'status'=>True,
                'data'=>$coreMaterial],200);
        }

    }


    public function store(Request $request)
    {

        // Reglas de validación para los datos del material principal
        $rules =[
            'cor_mat_name' => ['required', 'regex:/^[A-ZÁÉÍÓÚÜÀÈÌÒÙÑ\s]+$/'],
            'cor_mat_semester' => ['required', 'regex:/^[1-7]$/'],
            'car_id' => 'required|integer|exists:careers',
            'use_id' =>'required|integer|exists:users'
        ];

         // Realiza la validación de los datos recibidos
        $validator = Validator::make($request->input(), $rules);

        // Si la validación falla, devuelve los errores
        if ($validator->fails()) {
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ]);
        }else{

            // Crea un nuevo material principal
            $coreMaterial = new CoreMaterial($request->input());
            $coreMaterial->cor_mat_name = $request->cor_mat_name;
            $coreMaterial->cor_mat_semester = $request->cor_mat_semester ;
            $coreMaterial->car_id = $request->car_id ;
            $coreMaterial ->save();

             // Dispara un nuevo registro
            Controller::NewRegisterTrigger("Se realizó una inserción de datos en la tabla CoreMaterial ",3,$request->use_id);

            // Devuelve una respuesta exitosa junto con los datos del nuevo material principal
            return response()->json([
                'status' => True,
                'message' => 'Core material: '.$coreMaterial->cor_mat_name.' created successfully.',
                'data' => $coreMaterial
            ],200);
        }

    }


    public function show($id)
    {
        // Encuentra un material principal por su ID
        $coreMaterial = CoreMaterial::findOne($id);

        // Si no se encuentra el material, devuelve un mensaje de error
        if($coreMaterial == null){
            return response()->json([
            'status' => False,
            'message' => 'There are no core materials available.'
            ],400);
        }else{

            // Devuelve el material principal si se encuentra
            return response()->json([
                'status'=>True,
                'data'=>$coreMaterial],200);
        }
    }



    public function update(Request $request, $id)
    {

        // Encuentra el material principal por su ID
        $coreMaterial = CoreMaterial::find($id);

        // Si no se encuentra el material, devuelve un mensaje de error
        if($coreMaterial == null){
            return response()->json([
            'status' => False,
            'message' => 'There are no core materials available.'
            ]);
        }

        // Reglas de validación para actualizar los datos del material principal
        $rules =[
            'cor_mat_name' => ['required', 'regex:/^[A-ZÁÉÍÓÚÜÀÈÌÒÙÑ\s]+$/'],
            'cor_mat_semester' => ['required', 'regex:/^[1-7]$/'],
            'car_id' => ['required']
        ];

        // Realiza la validación de los datos recibidos
        $validator = Validator::make($request->input(), $rules);

         // Si la validación falla, devuelve los errores
        if ($validator->fails()) {
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ],400);
        }else{

            // Actualiza los datos del material principal
            $coreMaterial->cor_mat_name = $request->cor_mat_name;
            $coreMaterial->cor_mat_semester = $request->cor_mat_semester ;
            $coreMaterial->car_id = $request->car_id ;
            $coreMaterial ->save();

            // Dispara un nuevo registro
            Controller::NewRegisterTrigger("Se realizó una actualización de datos en la tabla CoreMaterial ",3,$request->use_id);

            // Devuelve una respuesta exitosa junto con los datos actualizados del material principal
            return response()->json([
                'status' => True,
                'message' => 'Core material: '.$coreMaterial->cor_mat_name.' updated successfully.',
                'data' => $coreMaterial
            ],200);
        }
    }


    public function destroy(Request $request)
    {
        // Dispara un nuevo registro para el intento de eliminación
        Controller::NewRegisterTrigger("Se intentó eliminar un dato en la tabla CoreMaterial ",3,$request->use_id);

        // Devuelve un mensaje indicando que esta función no está permitida
        return response()->json([
            'message' => 'This function is not allowed.'
        ],400);
    }
}
